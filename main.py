"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
A FastAPI-based system that detects scam messages, engages scammers autonomously,
and extracts actionable intelligence.

Architecture:
- Hybrid Scam Detection: Regex pre-filter + LLM validation
- Hybrid Intelligence Extraction: Regex for structured data + LLM for semantic analysis
- State Machine Responder: Conversation state tracking with response pools
- Three-tier Classification: Scam / Uncertain / Legitimate
"""

import os
import re
import json
import random
import logging
import time
from enum import Enum
from datetime import datetime
from typing import Optional, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from openai import AsyncOpenAI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("honeypot")

# Load .env file from the same directory as this script
load_dotenv(Path(__file__).parent / ".env")


# ============================================================================
# Configuration
# ============================================================================

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    API_KEY: str = Field(default="your-secret-api-key")
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    
    # OpenAI Configuration
    OPENAI_API_KEY: str = Field(default="")
    OPENAI_MODEL: str = Field(default="gpt-4o-mini")
    
    # Alternative: Groq Configuration (faster, cheaper)
    GROQ_API_KEY: str = Field(default="")
    GROQ_MODEL: str = Field(default="openai/gpt-oss-20b")
    USE_GROQ: bool = Field(default=False)
    
    # GUVI Callback Configuration
    GUVI_CALLBACK_URL: str = Field(
        default="https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # Agent Configuration
    MAX_MESSAGES: int = Field(default=20)
    MIN_MESSAGES: int = Field(default=5)
    
    # Hybrid Detection Configuration
    USE_HYBRID_DETECTION: bool = Field(default=True)
    LLM_THRESHOLD_LOW: float = Field(default=0.2)
    LLM_THRESHOLD_HIGH: float = Field(default=0.7)
    SCAM_THRESHOLD: float = Field(default=0.4)
    
    # Intelligence Configuration
    USE_LLM_INTELLIGENCE: bool = Field(default=True)
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()


# ============================================================================
# Enums and Constants
# ============================================================================

class MessageClassification(str, Enum):
    """Classification result for a message."""
    SCAM = "scam"
    UNCERTAIN = "uncertain"
    LEGITIMATE = "legitimate"


class ConversationState(str, Enum):
    """States for the conversation state machine."""
    INITIAL = "initial"
    CONFUSED = "confused"
    QUESTIONING = "questioning"
    HESITANT = "hesitant"
    ALMOST_COMPLYING = "almost_complying"
    EXTRACTING = "extracting"
    # States for legitimate conversations
    NORMAL_GREETING = "normal_greeting"
    NORMAL_CONVERSATION = "normal_conversation"


# ============================================================================
# Data Models (Matching GUVI Specification)
# ============================================================================

class Message(BaseModel):
    """
    Represents a single message in a conversation.
    
    Fields as per GUVI specification:
    - sender: "scammer" or "user"
    - text: Message content
    - timestamp: Epoch time format in milliseconds (e.g., 1770005528731)
    """
    sender: str = Field(..., description="Message sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Union[int, str] = Field(
        ..., 
        description="Epoch time in milliseconds (e.g., 1770005528731)",
        json_schema_extra={"example": 1770005528731}
    )
    
    def get_timestamp_ms(self) -> int:
        """Get timestamp as integer milliseconds."""
        if isinstance(self.timestamp, int):
            return self.timestamp
        try:
            return int(self.timestamp)
        except ValueError:
            # If it's an ISO string, convert to epoch ms
            from datetime import datetime
            try:
                dt = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
                return int(dt.timestamp() * 1000)
            except Exception:
                return int(datetime.utcnow().timestamp() * 1000)


class Metadata(BaseModel):
    """
    Optional metadata about the conversation.
    
    Fields as per GUVI specification:
    - channel: SMS / WhatsApp / Email / Chat
    - language: Language used (e.g., "English", "Hindi")
    - locale: Country or region (e.g., "IN", "US")
    """
    channel: Optional[str] = Field(default="SMS", description="Channel: SMS/WhatsApp/Email/Chat")
    language: Optional[str] = Field(default="English", description="Language used")
    locale: Optional[str] = Field(default="IN", description="Country or region code")


class IncomingRequest(BaseModel):
    """
    Request body for incoming messages.
    
    Fields as per GUVI specification:
    - sessionId: Unique session identifier (Required)
    - message: The latest incoming message (Required)
    - conversationHistory: All previous messages, empty [] for first message (Optional)
    - metadata: Channel, language, locale information (Optional but Recommended)
    """
    sessionId: str = Field(..., description="Unique session identifier")
    message: Message = Field(..., description="The latest incoming message")
    conversationHistory: list[Message] = Field(
        default_factory=list,
        description="All previous messages in the conversation. Empty [] for first message."
    )
    metadata: Optional[Metadata] = Field(
        default=None,
        description="Optional metadata: channel, language, locale"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123-session-id",
                "message": {
                    "sender": "scammer",
                    "text": "Your bank account has been blocked. Click here to verify.",
                    "timestamp": 1770005528731
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "SMS",
                    "language": "English",
                    "locale": "IN"
                }
            }
        }


class EngagementMetrics(BaseModel):
    """Metrics about the conversation engagement."""
    engagementDurationSeconds: int = Field(default=0, description="Duration of engagement in seconds")
    totalMessagesExchanged: int = Field(default=0, description="Total messages in conversation")


class AgentResponse(BaseModel):
    """
    Response from the honeypot agent as per GUVI specification Section 8.
    """
    status: str = Field(..., description="Response status: 'success' or 'error'")
    reply: str = Field(..., description="Agent's conversational response")
    scamDetected: bool = Field(default=False, description="Whether scam was detected")
    confidence: float = Field(default=0.0, description="Detection confidence (0-1)")
    scamTypes: list[str] = Field(default_factory=list, description="Types of scam detected")
    riskLevel: str = Field(default="safe", description="Risk level: safe, low, medium, high, critical")
    engagementMetrics: Optional[EngagementMetrics] = Field(default=None, description="Engagement metrics")
    extractedIntelligence: Optional[dict] = Field(default=None, description="Extracted intelligence data")
    agentNotes: Optional[str] = Field(default=None, description="Notes about scammer behavior")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "reply": "What? My account is blocked? Which bank are you calling from?",
                "scamDetected": True,
                "confidence": 0.85,
                "scamTypes": ["bank_fraud", "urgency"],
                "riskLevel": "high",
                "engagementMetrics": {
                    "engagementDurationSeconds": 420,
                    "totalMessagesExchanged": 18
                },
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": ["scammer@upi"],
                    "phishingLinks": []
                },
                "agentNotes": "Scammer used urgency tactics"
            }
        }


class ExtractedIntelligence(BaseModel):
    """
    Intelligence extracted from scammer interactions.
    
    Fields as per GUVI specification:
    - bankAccounts: List of bank account numbers
    - upiIds: List of UPI IDs
    - phishingLinks: List of malicious URLs
    - phoneNumbers: List of phone numbers
    - suspiciousKeywords: List of suspicious keywords detected
    """
    # Structured data (regex-extracted) - Required by GUVI
    bankAccounts: list[str] = Field(default_factory=list, description="Bank account numbers")
    upiIds: list[str] = Field(default_factory=list, description="UPI IDs like xxx@upi")
    phishingLinks: list[str] = Field(default_factory=list, description="Malicious/phishing URLs")
    phoneNumbers: list[str] = Field(default_factory=list, description="Phone numbers")
    suspiciousKeywords: list[str] = Field(default_factory=list, description="Suspicious keywords")
    
    # Semantic data (LLM-extracted) - Additional intelligence
    tactics: list[str] = Field(default_factory=list, description="Manipulation tactics used")
    impersonationTarget: str = Field(default="", description="Organization being impersonated")
    narrativeSummary: str = Field(default="", description="Summary of the scam narrative")


class FinalResultPayload(BaseModel):
    """
    Payload for GUVI callback endpoint.
    
    Sent to: POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
    
    Fields as per GUVI specification:
    - sessionId: Unique session ID from the platform
    - scamDetected: Whether scam intent was confirmed
    - totalMessagesExchanged: Total messages in the session
    - extractedIntelligence: All gathered intelligence
    - agentNotes: Summary of scammer behavior
    """
    sessionId: str = Field(..., description="Unique session ID from the platform")
    scamDetected: bool = Field(..., description="Whether scam intent was confirmed")
    totalMessagesExchanged: int = Field(..., description="Total messages exchanged")
    extractedIntelligence: dict = Field(..., description="All extracted intelligence")
    agentNotes: str = Field(..., description="Summary of scammer behavior")
    
    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123-session-id",
                "scamDetected": True,
                "totalMessagesExchanged": 18,
                "extractedIntelligence": {
                    "bankAccounts": ["XXXX-XXXX-XXXX"],
                    "upiIds": ["scammer@upi"],
                    "phishingLinks": ["http://malicious-link.example"],
                    "phoneNumbers": ["+91XXXXXXXXXX"],
                    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
                },
                "agentNotes": "Scammer used urgency tactics and payment redirection"
            }
        }


@dataclass
class DetectionResult:
    """Result from scam detection."""
    classification: MessageClassification
    confidence: float
    scam_types: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    reasoning: str = ""


# ============================================================================
# Session Management
# ============================================================================

class SessionData:
    """
    Stores data for a single conversation session.
    
    Enhanced for multi-turn conversation handling with:
    - Full conversation history
    - Conversation flow tracking
    - Scammer behavior analysis
    - Adaptive state management
    """
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scam_detected = False
        self.scam_confidence = 0.0
        self.classification = MessageClassification.UNCERTAIN
        self.messages: list[dict] = []
        self.intelligence = ExtractedIntelligence()
        self.agent_notes: list[str] = []
        self.callback_sent = False
        self.created_at = datetime.utcnow()
        self.scam_types: list[str] = []
        self.conversation_state = ConversationState.INITIAL
        
        # Multi-turn conversation tracking
        self.turn_count = 0  # Number of back-and-forth exchanges
        self.scammer_pressure_level = 0  # 0-10 scale of how aggressive scammer is
        self.our_compliance_shown = 0  # 0-10 scale of how compliant we appear
        self.topics_covered: list[str] = []  # Track what topics have been discussed
        self.last_scammer_tactic: str = ""  # Last tactic used by scammer
        self.conversation_summary: str = ""  # Brief summary for context
    
    def add_message(self, sender: str, text: str, timestamp: str):
        """Add a message to the session history with context tracking."""
        self.messages.append({
            "sender": sender,
            "text": text,
            "timestamp": timestamp
        })
        
        # Update turn count (each pair of messages is a turn)
        if sender != "user":
            self.turn_count += 1
            # Analyze scammer's message for pressure tactics
            self._analyze_scammer_message(text)
    
    def _analyze_scammer_message(self, text: str):
        """Analyze scammer's message for adaptive response."""
        text_lower = text.lower()
        
        # Detect pressure tactics
        urgency_words = ['urgent', 'immediately', 'now', 'today', 'hurry', 'quick', 'fast']
        threat_words = ['block', 'suspend', 'freeze', 'legal', 'police', 'arrest', 'fine']
        
        urgency_count = sum(1 for word in urgency_words if word in text_lower)
        threat_count = sum(1 for word in threat_words if word in text_lower)
        
        # Update pressure level (increases with aggressive tactics)
        pressure_increase = urgency_count + (threat_count * 2)
        self.scammer_pressure_level = min(10, self.scammer_pressure_level + pressure_increase)
        
        # Track last tactic
        if threat_count > 0:
            self.last_scammer_tactic = "threat"
        elif urgency_count > 0:
            self.last_scammer_tactic = "urgency"
        elif any(word in text_lower for word in ['verify', 'confirm', 'update']):
            self.last_scammer_tactic = "verification"
        elif any(word in text_lower for word in ['click', 'link', 'visit']):
            self.last_scammer_tactic = "link_share"
    
    def get_adaptive_state(self) -> ConversationState:
        """
        Get conversation state adapted to scammer's behavior.
        
        This enables dynamic response adaptation based on:
        - Turn count (conversation progression)
        - Scammer pressure level
        - Our shown compliance
        """
        # Early conversation
        if self.turn_count <= 2:
            return ConversationState.CONFUSED
        
        # If scammer is very aggressive, show we're getting scared but compliant
        if self.scammer_pressure_level >= 7:
            return ConversationState.ALMOST_COMPLYING
        
        # Mid-conversation progression
        if self.turn_count <= 4:
            if self.scammer_pressure_level >= 4:
                return ConversationState.HESITANT
            return ConversationState.QUESTIONING
        
        # Later conversation - start extracting information
        if self.turn_count <= 7:
            return ConversationState.ALMOST_COMPLYING
        
        # Deep conversation - maximize intelligence extraction
        return ConversationState.EXTRACTING
    
    def increase_compliance(self):
        """Increase our shown compliance (for realistic progression)."""
        self.our_compliance_shown = min(10, self.our_compliance_shown + 1)
    
    @property
    def total_messages(self) -> int:
        return len(self.messages)
    
    def get_incoming_messages(self) -> list[dict]:
        """Get all messages from the other party (not 'user')."""
        return [msg for msg in self.messages if msg.get('sender') != 'user']
    
    def get_recent_context(self, n: int = 3) -> str:
        """Get recent conversation context as string for AI prompts."""
        recent = self.messages[-n*2:] if len(self.messages) >= n*2 else self.messages
        return " | ".join([f"{m['sender']}: {m['text'][:50]}" for m in recent])


class SessionManager:
    """Manages all active conversation sessions."""
    
    def __init__(self):
        self._sessions: dict[str, SessionData] = {}
    
    def get_or_create(self, session_id: str) -> SessionData:
        """Get existing session or create a new one."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionData(session_id)
        return self._sessions[session_id]
    
    def get(self, session_id: str) -> Optional[SessionData]:
        """Get a session by ID."""
        return self._sessions.get(session_id)
    
    def delete(self, session_id: str):
        """Delete a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]


# Global session manager
session_manager = SessionManager()


# ============================================================================
# Hybrid Scam Detection Module
# ============================================================================

class HybridScamDetector:
    """
    Hybrid scam detection using regex pre-filter and LLM validation.
    
    Three-tier classification:
    - SCAM: High confidence scam (confidence > threshold_high)
    - LEGITIMATE: Clearly not a scam (confidence < threshold_low)
    - UNCERTAIN: Needs LLM validation (threshold_low <= confidence <= threshold_high)
    """
    
    # Scam indicator patterns with weights
    SCAM_PATTERNS = {
        # Urgency patterns
        r'\b(urgent|immediately|today|now|quick|fast|hurry)\b': {
            'weight': 0.15, 'type': 'urgency', 'keyword': 'urgent'
        },
        # Call immediately pattern
        r'\b(call|contact|dial)\s*(us|this|the)?\s*(number)?\s*(immediately|now|urgent|today)\b': {
            'weight': 0.25, 'type': 'urgency', 'keyword': 'call immediately'
        },
        r'\b(block(ed)?|suspend(ed)?|deactivat(e|ed)|freez(e|ing)|locked?|compromised?|hacked?)\b': {
            'weight': 0.25, 'type': 'threat', 'keyword': 'account blocked'
        },
        # Compromised account pattern
        r'\b(account|password|data)\s*(has\s*been|is|was)?\s*(compromised|hacked|breached)\b': {
            'weight': 0.35, 'type': 'security_threat', 'keyword': 'account compromised'
        },
        
        # Action demands
        r'\b(verify|confirm|validate|authenticate)\s*(your|ur|the)?\s*(account|details|information|identity)\b': {
            'weight': 0.2, 'type': 'action_demand', 'keyword': 'verify now'
        },
        r'\b(click|tap|visit|go\s*to|open)\s*(this|the|here|link|url)\b': {
            'weight': 0.25, 'type': 'link_prompt', 'keyword': 'click link'
        },
        
        # Financial terms (only suspicious in certain contexts)
        r'\b(bank\s*account|savings|current\s*account)\s*(will\s*be|is|has\s*been)\s*(block|suspend|freez|deactivat)': {
            'weight': 0.3, 'type': 'financial_threat', 'keyword': 'account threat'
        },
        r'\b(upi|gpay|paytm|phonepe|bhim)\s*(id|account)?\s*(to\s*)?(verify|confirm|send|transfer|pay)\b': {
            'weight': 0.25, 'type': 'payment_request', 'keyword': 'UPI request'
        },
        r'\b(share|send|provide|give)\s*(your|ur|the)?\s*(otp|pin|cvv|password|passcode|mpin)\b': {
            'weight': 0.4, 'type': 'credential_request', 'keyword': 'OTP request'
        },
        # Card details request
        r'\b(share|send|provide|give)\s*(your|ur|the)?\s*(card\s*(number|no|details)|credit\s*card|debit\s*card|cvv)\b': {
            'weight': 0.45, 'type': 'card_fraud', 'keyword': 'card details request'
        },
        # Refund scam
        r'\b(refund|cashback|reimbursement)\s*(of)?\s*(rs\.?|inr|₹)?\s*\d*\s*(pending|processing|available)\b': {
            'weight': 0.3, 'type': 'refund_scam', 'keyword': 'refund scam'
        },
        r'\b(pending\s*refund|refund\s*(pending|available|processing))\b': {
            'weight': 0.3, 'type': 'refund_scam', 'keyword': 'refund scam'
        },
        
        # Money related
        r'\b(transfer|send|pay|deposit)\s*(rs\.?|inr|₹)?\s*\d+': {
            'weight': 0.25, 'type': 'money_request', 'keyword': 'money transfer'
        },
        r'\b(prize|winner|won|lottery|lucky\s*draw|reward|cashback)\s*(of)?\s*(rs\.?|inr|₹)?\s*\d*': {
            'weight': 0.3, 'type': 'prize_scam', 'keyword': 'prize winner'
        },
        
        # Impersonation with action
        r'\b(rbi|reserve\s*bank|income\s*tax|it\s*department|police|cyber\s*cell)\b.*\b(verify|action|complaint|case)\b': {
            'weight': 0.3, 'type': 'authority_impersonation', 'keyword': 'authority impersonation'
        },
        r'\b(sbi|hdfc|icici|axis|bank)\s*(customer\s*care|support|security|alert)\b': {
            'weight': 0.25, 'type': 'bank_impersonation', 'keyword': 'bank impersonation'
        },
        
        # Threat patterns
        r'\b(legal\s*action|police\s*complaint|fir|arrest|jail|fine|penalty)\b': {
            'weight': 0.25, 'type': 'threat', 'keyword': 'legal threat'
        },
        r'\b(within|in)\s*\d+\s*(hour|minute|hr|min)s?\b': {
            'weight': 0.15, 'type': 'time_pressure', 'keyword': 'time pressure'
        },
        
        # Suspicious links
        r'https?://[^\s]*\.(xyz|tk|ml|ga|cf|gq|top|pw|cc|click|link)/': {
            'weight': 0.3, 'type': 'suspicious_link', 'keyword': 'suspicious link'
        },
        r'bit\.ly/|tinyurl\.com/|short\.': {
            'weight': 0.2, 'type': 'shortened_link', 'keyword': 'shortened link'
        },
        
        # KYC scam
        r'\b(kyc|know\s*your\s*customer)\s*(update|verify|expire|pending|fail)\b': {
            'weight': 0.3, 'type': 'kyc_scam', 'keyword': 'KYC update'
        },
        
        # Job/loan scam
        r'\b(job\s*offer|work\s*from\s*home|earn\s*(rs\.?|₹)?\s*\d+|loan\s*(approved|sanction)|pre-?approved)\b': {
            'weight': 0.25, 'type': 'job_loan_scam', 'keyword': 'fake offer'
        },
        
        # Remote access scam
        r'\b(anydesk|teamviewer|quick\s*support|remote\s*access)\b': {
            'weight': 0.35, 'type': 'remote_access_scam', 'keyword': 'remote access'
        },
    }
    
    # Patterns that indicate legitimate messages (reduce scam score)
    LEGITIMATE_PATTERNS = {
        r'^(hi|hello|hey|good\s*(morning|afternoon|evening))[\s,!.]*$': -0.3,
        r'^\s*(thanks|thank\s*you|ok|okay|sure|yes|no)\s*[.!]*\s*$': -0.2,
        r'\b(meeting|appointment|schedule|tomorrow|yesterday)\b': -0.15,
        r'\b(how\s*are\s*you|what\'?s\s*up|how\s*is)\b': -0.2,
        r'^(wrong\s*number|sorry|my\s*mistake)\b': -0.25,
    }
    
    def __init__(self):
        """Initialize the hybrid detector with LLM client if available."""
        if settings.USE_GROQ and settings.GROQ_API_KEY:
            self.llm_client = AsyncOpenAI(
                api_key=settings.GROQ_API_KEY,
                base_url="https://api.groq.com/openai/v1"
            )
            self.llm_model = settings.GROQ_MODEL
        elif settings.OPENAI_API_KEY:
            self.llm_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.llm_model = settings.OPENAI_MODEL
        else:
            self.llm_client = None
            self.llm_model = None
    
    async def detect(
        self,
        text: str,
        conversation_history: list[Message] = None
    ) -> DetectionResult:
        """
        Detect if a message contains scam intent using hybrid approach.
        
        Stage 1: Fast regex pre-filter
        Stage 2: LLM validation for uncertain cases
        """
        # Stage 1: Regex-based detection
        regex_result = self._regex_detect(text, conversation_history)
        
        # If high confidence either way, return immediately
        if not settings.USE_HYBRID_DETECTION or not self.llm_client:
            return regex_result
        
        # Only use LLM for uncertain cases
        if (regex_result.confidence > settings.LLM_THRESHOLD_HIGH or
            regex_result.confidence < settings.LLM_THRESHOLD_LOW):
            return regex_result
        
        # Stage 2: LLM validation
        try:
            llm_result = await self._llm_detect(text, conversation_history)
            return self._merge_results(regex_result, llm_result)
        except Exception as e:
            print(f"LLM detection error: {e}")
            return regex_result
    
    def _regex_detect(
        self,
        text: str,
        conversation_history: list[Message] = None
    ) -> DetectionResult:
        """Fast regex-based scam detection."""
        text_lower = text.lower()
        
        # Combine with history for context
        full_text = text_lower
        if conversation_history:
            for msg in conversation_history:
                if msg.sender != "user":
                    full_text += " " + msg.text.lower()
        
        total_weight = 0.0
        detected_types = set()
        detected_keywords = set()
        
        # Check scam patterns
        for pattern, info in self.SCAM_PATTERNS.items():
            if re.search(pattern, full_text, re.IGNORECASE):
                total_weight += info['weight']
                detected_types.add(info['type'])
                detected_keywords.add(info['keyword'])
        
        # Check legitimate patterns (reduce weight)
        for pattern, weight_reduction in self.LEGITIMATE_PATTERNS.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                total_weight += weight_reduction  # This is negative
        
        # Ensure weight is between 0 and 1
        confidence = max(0.0, min(total_weight, 1.0))
        
        # Classify based on confidence
        if confidence >= settings.LLM_THRESHOLD_HIGH:
            classification = MessageClassification.SCAM
        elif confidence <= settings.LLM_THRESHOLD_LOW:
            classification = MessageClassification.LEGITIMATE
        else:
            classification = MessageClassification.UNCERTAIN
        
        return DetectionResult(
            classification=classification,
            confidence=confidence,
            scam_types=list(detected_types),
            keywords=list(detected_keywords),
            reasoning=f"Regex detection: {len(detected_types)} scam patterns matched"
        )
    
    async def _llm_detect(
        self,
        text: str,
        conversation_history: list[Message] = None
    ) -> DetectionResult:
        """LLM-based scam detection for uncertain cases."""
        
        system_prompt = """You are a scam detection expert. Analyze the given message and conversation to determine if it's a scam attempt.

Consider these scam indicators:
- Urgency or pressure tactics
- Requests for personal/financial information
- Impersonation of banks, government, or companies
- Suspicious links or contact requests
- Too-good-to-be-true offers
- Threats of account blocking, legal action, etc.

Also consider legitimate message patterns:
- Normal greetings and small talk
- Business/personal appointment discussions
- Genuine inquiries without pressure
- Wrong number situations

Respond with ONLY a JSON object (no markdown, no explanation):
{
    "is_scam": true/false,
    "confidence": 0.0-1.0,
    "scam_types": ["type1", "type2"],
    "reasoning": "Brief explanation"
}"""

        # Build context
        context = ""
        if conversation_history:
            for msg in conversation_history[-5:]:  # Last 5 messages
                context += f"{msg.sender}: {msg.text}\n"
        context += f"Current message: {text}"
        
        try:
            print(f"🤖 [GROQ API CALL] LLM Validation - Model: {self.llm_model}")
            
            # Retry logic for better model compatibility
            result_text = ""
            for attempt in range(3):
                try:
                    response = await self.llm_client.chat.completions.create(
                        model=self.llm_model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": context}
                        ],
                        max_tokens=200,
                        temperature=0.1 + (attempt * 0.1),  # Increase temp on retry
                    )
                    result_text = response.choices[0].message.content.strip() if response.choices[0].message.content else ""
                    if result_text:
                        print(f"✅ [GROQ LLM] Validation response received: {len(result_text)} chars")
                        break
                    print(f"⚠️ [GROQ LLM RETRY] Attempt {attempt+1} returned empty")
                except Exception as retry_err:
                    print(f"⚠️ [GROQ LLM RETRY] Attempt {attempt+1} failed: {retry_err}")
            
            if not result_text:
                raise ValueError("Empty LLM validation response")
            # Clean up potential markdown
            result_text = result_text.replace("```json", "").replace("```", "").strip()
            result = json.loads(result_text)
            
            confidence = float(result.get("confidence", 0.5))
            is_scam = result.get("is_scam", False)
            
            if is_scam and confidence >= settings.SCAM_THRESHOLD:
                classification = MessageClassification.SCAM
            elif not is_scam and confidence <= (1 - settings.SCAM_THRESHOLD):
                classification = MessageClassification.LEGITIMATE
            else:
                classification = MessageClassification.UNCERTAIN
            
            return DetectionResult(
                classification=classification,
                confidence=confidence if is_scam else (1 - confidence),
                scam_types=result.get("scam_types", []),
                keywords=[],
                reasoning=result.get("reasoning", "LLM analysis")
            )
            
        except Exception as e:
            print(f"LLM detection parse error: {e}")
            return DetectionResult(
                classification=MessageClassification.UNCERTAIN,
                confidence=0.5,
                reasoning=f"LLM error: {str(e)}"
            )
    
    def _merge_results(
        self,
        regex_result: DetectionResult,
        llm_result: DetectionResult
    ) -> DetectionResult:
        """Merge regex and LLM detection results."""
        # Weighted average: 40% regex, 60% LLM
        merged_confidence = (regex_result.confidence * 0.4) + (llm_result.confidence * 0.6)
        
        # Combine scam types and keywords
        all_types = list(set(regex_result.scam_types + llm_result.scam_types))
        all_keywords = list(set(regex_result.keywords + llm_result.keywords))
        
        # Final classification
        if merged_confidence >= settings.LLM_THRESHOLD_HIGH:
            classification = MessageClassification.SCAM
        elif merged_confidence <= settings.LLM_THRESHOLD_LOW:
            classification = MessageClassification.LEGITIMATE
        else:
            # For uncertain, defer to LLM's judgment
            classification = llm_result.classification
        
        return DetectionResult(
            classification=classification,
            confidence=merged_confidence,
            scam_types=all_types,
            keywords=all_keywords,
            reasoning=f"Hybrid: Regex({regex_result.confidence:.2f}) + LLM({llm_result.confidence:.2f}). {llm_result.reasoning}"
        )


# Global detector instance
scam_detector = HybridScamDetector()


# ============================================================================
# Hybrid Intelligence Extraction Module
# ============================================================================

class HybridIntelligenceExtractor:
    """
    Extracts actionable intelligence using regex + LLM.
    
    - Regex: Structured data (phone numbers, UPI IDs, links, account numbers)
    - LLM: Semantic analysis (tactics, impersonation target, narrative summary)
    """
    
    # Regex patterns for extracting specific information
    PATTERNS = {
        'bank_accounts': [
            r'\b\d{9,18}\b',  # Account numbers (9-18 digits)
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Card-like numbers
        ],
        'upi_ids': [
            r'\b[\w.\-]+@(upi|ybl|okaxis|okicici|okhdfcbank|paytm|ibl|sbi|axl|apl|axisb|idfcbank|kotak)\b',
            r'\b[\w.\-]+@[\w]{2,10}\b',  # General UPI pattern
        ],
        'phishing_links': [
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            r'bit\.ly/[^\s]+',
            r'tinyurl\.com/[^\s]+',
            r'[\w]+\.(xyz|tk|ml|ga|cf|gq|top|pw|cc|click)/[^\s]*',
        ],
        'phone_numbers': [
            r'\+91[\s-]?\d{10}\b',
            r'\b[6-9]\d{9}\b',  # Indian mobile numbers
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
        ],
    }
    
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'immediately', 'verify now', 'account blocked', 'suspended',
        'click here', 'share otp', 'send money', 'prize winner', 'lottery',
        'kyc update', 'bank verification', 'security alert', 'unauthorized',
        'refund', 'cashback', 'reward', 'limited time', 'act now', 'expire',
        'legal action', 'police', 'arrest', 'fine', 'penalty', 'freeze',
        'anydesk', 'teamviewer', 'remote access', 'screen share',
    ]
    
    def __init__(self):
        """Initialize with LLM client if available."""
        if settings.USE_GROQ and settings.GROQ_API_KEY:
            self.llm_client = AsyncOpenAI(
                api_key=settings.GROQ_API_KEY,
                base_url="https://api.groq.com/openai/v1"
            )
            self.llm_model = settings.GROQ_MODEL
        elif settings.OPENAI_API_KEY:
            self.llm_client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.llm_model = settings.OPENAI_MODEL
        else:
            self.llm_client = None
            self.llm_model = None
    
    async def extract(self, messages: list[dict]) -> ExtractedIntelligence:
        """Extract intelligence using hybrid approach."""
        # First, extract structured data with regex
        intelligence = self._regex_extract(messages)
        
        # Then, add semantic analysis with LLM if available and enabled
        if self.llm_client and settings.USE_LLM_INTELLIGENCE and len(messages) >= 2:
            try:
                semantic = await self._llm_extract(messages)
                intelligence.tactics = semantic.get("tactics", [])
                intelligence.impersonationTarget = semantic.get("impersonation_target", "")
                intelligence.narrativeSummary = semantic.get("narrative_summary", "")
            except Exception as e:
                print(f"LLM intelligence extraction error: {e}")
        
        return intelligence
    
    def _regex_extract(self, messages: list[dict]) -> ExtractedIntelligence:
        """Extract structured data using regex patterns."""
        intelligence = ExtractedIntelligence()
        
        # Combine all non-user messages for extraction
        other_texts = " ".join(
            msg['text'] for msg in messages if msg.get('sender') != 'user'
        )
        
        # Extract bank accounts
        for pattern in self.PATTERNS['bank_accounts']:
            matches = re.findall(pattern, other_texts)
            for match in matches:
                clean = match.replace('-', '').replace(' ', '')
                if len(clean) >= 9:
                    masked = self._mask_sensitive(match)
                    if masked not in intelligence.bankAccounts:
                        intelligence.bankAccounts.append(masked)
        
        # Extract UPI IDs
        for pattern in self.PATTERNS['upi_ids']:
            matches = re.findall(pattern, other_texts, re.IGNORECASE)
            for match in matches:
                # Handle tuple results from regex groups
                upi_id = match if isinstance(match, str) else match[0] if match else ""
                if '@' in other_texts:
                    # Find full UPI ID
                    full_matches = re.findall(r'\b[\w.\-]+@[\w]+\b', other_texts, re.IGNORECASE)
                    for full_match in full_matches:
                        if full_match not in intelligence.upiIds:
                            intelligence.upiIds.append(full_match)
        
        # Extract phishing links
        for pattern in self.PATTERNS['phishing_links']:
            matches = re.findall(pattern, other_texts)
            for match in matches:
                if match not in intelligence.phishingLinks:
                    intelligence.phishingLinks.append(match)
        
        # Extract phone numbers
        for pattern in self.PATTERNS['phone_numbers']:
            matches = re.findall(pattern, other_texts)
            for match in matches:
                formatted = self._format_phone(match)
                if formatted and formatted not in intelligence.phoneNumbers:
                    intelligence.phoneNumbers.append(formatted)
        
        # Extract suspicious keywords
        text_lower = other_texts.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in text_lower and keyword not in intelligence.suspiciousKeywords:
                intelligence.suspiciousKeywords.append(keyword)
        
        return intelligence
    
    async def _llm_extract(self, messages: list[dict]) -> dict:
        """Extract semantic intelligence using LLM."""
        
        system_prompt = """Analyze this scam conversation and extract intelligence.

Return ONLY a JSON object (no markdown):
{
    "tactics": ["list of manipulation tactics used, e.g., urgency, authority, fear"],
    "impersonation_target": "organization being impersonated, e.g., SBI Bank, Income Tax Dept",
    "narrative_summary": "Brief 1-2 sentence summary of the scam story/scheme"
}

If not enough information, return empty values."""

        # Build conversation text
        conversation = "\n".join(
            f"{msg['sender']}: {msg['text']}" for msg in messages[-10:]
        )
        
        try:
            print(f"🤖 [GROQ API CALL] LLM Extraction - Model: {self.llm_model}")
            
            # Retry logic for better model compatibility
            result_text = ""
            for attempt in range(3):
                try:
                    response = await self.llm_client.chat.completions.create(
                        model=self.llm_model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": conversation}
                        ],
                        max_tokens=200,
                        temperature=0.1 + (attempt * 0.1),
                    )
                    result_text = response.choices[0].message.content.strip() if response.choices[0].message.content else ""
                    if result_text:
                        print(f"✅ [GROQ LLM] Extraction response received: {len(result_text)} chars")
                        break
                    print(f"⚠️ [GROQ LLM RETRY] Extraction attempt {attempt+1} returned empty")
                except Exception as retry_err:
                    print(f"⚠️ [GROQ LLM RETRY] Extraction attempt {attempt+1} failed: {retry_err}")
            
            if not result_text:
                return {}
            
            result_text = result_text.replace("```json", "").replace("```", "").strip()
            return json.loads(result_text)
            
        except Exception as e:
            print(f"LLM extraction error: {e}")
            return {}
    
    @staticmethod
    def _mask_sensitive(value: str) -> str:
        """Mask sensitive information for privacy."""
        clean = value.replace('-', '').replace(' ', '')
        if len(clean) > 4:
            return 'X' * (len(clean) - 4) + clean[-4:]
        return clean
    
    @staticmethod
    def _format_phone(phone: str) -> str:
        """Format phone number consistently."""
        digits = re.sub(r'\D', '', phone)
        if len(digits) == 10:
            return f"+91{digits}"
        elif len(digits) == 12 and digits.startswith('91'):
            return f"+{digits}"
        elif len(digits) >= 10:
            return f"+{digits}"
        return ""


# Global extractor instance
intelligence_extractor = HybridIntelligenceExtractor()


# ============================================================================
# State Machine Responder (Fallback)
# ============================================================================

class StateMachineResponder:
    """
    State machine for generating contextual fallback responses.
    
    Tracks conversation state and provides appropriate responses from pools.
    Handles both scam engagement and legitimate conversation scenarios.
    
    Key Features:
    1. Multi-turn awareness - Remembers conversation progression
    2. Dynamic adaptation - Responds to scammer pressure
    3. Human-like behavior - Natural language with emotions
    4. No scam revelation - All responses maintain naive persona
    """
    
    # Response pools for scam engagement states - NEVER reveal scam awareness
    SCAM_RESPONSE_POOLS = {
        ConversationState.INITIAL: [
            "Hello? Who is this?",
            "Yes, speaking. What is this about?",
            "Umm, I don't understand. Can you explain?",
            "Huh? What is this regarding?",
        ],
        ConversationState.CONFUSED: [
            "What? I don't understand. What account are you talking about?",
            "Sorry, can you explain more clearly? I'm a bit confused here.",
            "Which bank? I have accounts in different banks, you know.",
            "Hmm, I'm not sure what you mean. Can you start from the beginning?",
            "Huh? My account? What happened to my account?",
            "Wait wait, slow down. What are you saying?",
            "I'm confused. My account has a problem?",
            "What do you mean blocked? I used it yesterday only!",
        ],
        ConversationState.QUESTIONING: [
            "But how do I know this is really from my bank?",
            "Can you tell me which branch you're calling from?",
            "My son works in IT, he always says verify first. Can you give me some proof?",
            "What's your employee ID? I want to verify.",
            "Hmm, banks don't usually call like this na? How can I be sure?",
            "Can I call back on the official bank number? I have it saved.",
            "My daughter said never share details on phone. But this is genuine right?",
            "Wait, let me think. How do I know you're really from the bank?",
        ],
        ConversationState.HESITANT: [
            "I'm not sure about this... My family always warns me to be careful.",
            "Hmm, let me think about it. Can I call you back?",
            "I need to ask my son first. He handles all my banking matters.",
            "This doesn't feel right. Why are you asking for this over phone?",
            "I'm at work right now. Can we do this later please?",
            "My neighbor got cheated last month. I need to be careful na.",
            "Okay but I'm scared now. What if something goes wrong?",
            "Umm, I don't know. My husband usually handles these things.",
            "Can you give me some time? I want to check first.",
            "I'm worried now. Is my money safe?",
        ],
        ConversationState.ALMOST_COMPLYING: [
            "OK, I want to help. What exactly do you need from me?",
            "Fine fine, tell me step by step what I should do.",
            "Alright, but please explain slowly. I'm not good with technology.",
            "OK OK, I'll do it. Just tell me clearly what information you need.",
            "I don't want my account blocked! What should I do?",
            "Okay, I'm opening my phone. What do I do now?",
            "Tell me tell me, I'll do whatever you say. I'm scared.",
            "Alright, I trust you. What details do you need?",
            "OK, I believe you. Please help me fix this problem.",
        ],
        ConversationState.EXTRACTING: [
            "Which UPI ID should I send to? Please spell it out slowly.",
            "What's the account number? Let me write it down carefully.",
            "The link is not opening on my phone. Can you send it again?",
            "How much money should I transfer? And to which account exactly?",
            "Please give me the details again slowly. I'm noting them down.",
            "What's the correct number to call? I'll write it down.",
            "OK I have a pen now. Tell me the account number again.",
            "The link you sent, is it starting with http? I can't see properly.",
            "Should I transfer now only? How much exactly?",
            "Which app should I use? Google Pay or PhonePe?",
        ],
    }
    
    # Response pools for legitimate conversations
    LEGITIMATE_RESPONSE_POOLS = {
        ConversationState.NORMAL_GREETING: [
            "Hello! How can I help you?",
            "Hi there! Who is this please?",
            "Hello, may I know who's calling?",
            "Hi! Sorry, I don't have this number saved. Who is this?",
            "Hello! I don't recognize this number.",
        ],
        ConversationState.NORMAL_CONVERSATION: [
            "I think you may have the wrong number.",
            "Sorry, I don't recognize this number. May I know who this is?",
            "I'm not sure I understand. Could you clarify?",
            "Sorry, I think there's been some confusion here.",
            "I don't think I'm the person you're looking for.",
            "Wrong number maybe? I don't know anyone by that name.",
        ],
    }
    
    # Additional responses for pressure adaptation (when scammer is aggressive)
    HIGH_PRESSURE_RESPONSES = [
        "Okay okay, please don't shout. I'll do it. Just tell me what to do!",
        "I'm scared now! Please help me, I'll do whatever you say.",
        "Oh god, I don't want any problem. Tell me quickly what to do.",
        "Please please help me. I'm very worried. What should I do?",
        "OK OK, I believe you. I'm panicking. Just guide me step by step.",
    ]
    
    # Keyword triggers for state transitions
    STATE_TRIGGERS = {
        'urgency': ['urgent', 'immediately', 'now', 'today', 'hurry', 'fast', 'quick'],
        'threat': ['block', 'suspend', 'freeze', 'deactivate', 'legal', 'police', 'arrest'],
        'request': ['upi', 'account', 'otp', 'pin', 'password', 'transfer', 'send', 'pay'],
        'link': ['click', 'link', 'url', 'visit', 'open'],
        'prize': ['prize', 'winner', 'lottery', 'won', 'reward', 'cashback'],
    }
    
    def get_response(
        self,
        current_message: str,
        session: SessionData,
        classification: MessageClassification
    ) -> str:
        """
        Get appropriate response with dynamic adaptation.
        
        Adapts based on:
        - Current conversation state
        - Scammer pressure level
        - Message content
        - Conversation history length
        """
        
        text_lower = current_message.lower()
        
        # Check scammer pressure level for dynamic adaptation
        has_threat = any(word in text_lower for word in self.STATE_TRIGGERS['threat'])
        has_urgency = any(word in text_lower for word in self.STATE_TRIGGERS['urgency'])
        
        # If scammer is very aggressive, respond with fear/compliance
        if has_threat and has_urgency and hasattr(session, 'scammer_pressure_level'):
            if session.scammer_pressure_level >= 5 or session.total_messages >= 4:
                return random.choice(self.HIGH_PRESSURE_RESPONSES)
        
        # Update state based on classification and message content
        new_state = self._determine_state(current_message, session, classification)
        session.conversation_state = new_state
        
        # Select response pool based on classification
        if classification == MessageClassification.LEGITIMATE:
            pool = self.LEGITIMATE_RESPONSE_POOLS.get(
                new_state,
                self.LEGITIMATE_RESPONSE_POOLS[ConversationState.NORMAL_CONVERSATION]
            )
        else:
            pool = self.SCAM_RESPONSE_POOLS.get(
                new_state,
                self.SCAM_RESPONSE_POOLS[ConversationState.CONFUSED]
            )
        
        # Select random response from pool
        response = random.choice(pool)
        
        # Personalize response based on detected keywords
        response = self._personalize_response(response, current_message, session)
        
        return response
    
    def _determine_state(
        self,
        message: str,
        session: SessionData,
        classification: MessageClassification
    ) -> ConversationState:
        """
        Determine conversation state with adaptive logic.
        
        Uses session's adaptive state if available for better multi-turn handling.
        """
        
        text_lower = message.lower()
        message_count = session.total_messages
        current_state = session.conversation_state
        
        # Handle legitimate messages
        if classification == MessageClassification.LEGITIMATE:
            if any(word in text_lower for word in ['hi', 'hello', 'hey', 'good morning', 'good evening']):
                return ConversationState.NORMAL_GREETING
            return ConversationState.NORMAL_CONVERSATION
        
        # Use adaptive state from enhanced SessionData if available
        if hasattr(session, 'get_adaptive_state'):
            return session.get_adaptive_state()
        
        # Fallback to original state machine logic
        if current_state == ConversationState.INITIAL:
            return ConversationState.CONFUSED
        
        # Check for escalation triggers
        has_urgency = any(word in text_lower for word in self.STATE_TRIGGERS['urgency'])
        has_threat = any(word in text_lower for word in self.STATE_TRIGGERS['threat'])
        has_request = any(word in text_lower for word in self.STATE_TRIGGERS['request'])
        has_link = any(word in text_lower for word in self.STATE_TRIGGERS['link'])
        
        # State transitions based on scammer behavior (dynamic adaptation)
        if current_state == ConversationState.CONFUSED:
            if has_threat or has_urgency:
                return ConversationState.QUESTIONING
            return ConversationState.CONFUSED
        
        elif current_state == ConversationState.QUESTIONING:
            if has_request or has_link:
                return ConversationState.HESITANT
            if message_count > 4:
                return ConversationState.HESITANT
            return ConversationState.QUESTIONING
        
        elif current_state == ConversationState.HESITANT:
            if has_urgency or has_threat:
                return ConversationState.ALMOST_COMPLYING
            if message_count > 6:
                return ConversationState.ALMOST_COMPLYING
            return ConversationState.HESITANT
        
        elif current_state == ConversationState.ALMOST_COMPLYING:
            if has_request or has_link:
                return ConversationState.EXTRACTING
            return ConversationState.ALMOST_COMPLYING
        
        elif current_state == ConversationState.EXTRACTING:
            # Stay in extracting or cycle back
            if message_count > 10:
                return ConversationState.ALMOST_COMPLYING
            return ConversationState.EXTRACTING
        
        return ConversationState.CONFUSED
    
    def _personalize_response(self, response: str, message: str, session: SessionData) -> str:
        """
        Add personalization based on message content and session context.
        
        Ensures responses feel human and contextually appropriate.
        """
        text_lower = message.lower()
        
        # Detect bank name for personalization
        banks = ['sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'bob']
        detected_bank = None
        for bank in banks:
            if bank in text_lower:
                detected_bank = bank.upper()
                break
        
        if detected_bank:
            response = response.replace('{bank}', detected_bank)
            # Add bank-specific context
            if 'account' in response.lower() and random.random() < 0.3:
                response += f" My {detected_bank} account right?"
        else:
            response = response.replace('{bank}', 'the bank')
        
        # Add multi-turn context references occasionally
        if hasattr(session, 'turn_count') and session.turn_count > 2:
            if random.random() < 0.2:
                continuity_phrases = [
                    " You mentioned this before na?",
                    " Like you said earlier.",
                    " Same thing you were saying.",
                ]
                response += random.choice(continuity_phrases)
        
        return response


# Global responder instance
state_machine_responder = StateMachineResponder()


# ============================================================================
# AI Agent Module
# ============================================================================

class HoneypotAgent:
    """
    AI Agent that engages scammers with believable human-like responses.
    
    Key Behavior Expectations:
    1. Handle multi-turn conversations - Track context across messages
    2. Adapt responses dynamically - Change behavior based on scammer tactics
    3. Avoid revealing scam detection - Never hint that we know it's a scam
    4. Behave like a real human - Natural language, emotions, hesitation
    5. Perform self-correction - Fix responses that seem too robotic
    """
    
    # Forbidden phrases that would reveal scam detection
    FORBIDDEN_PHRASES = [
        'scam', 'scammer', 'fraud', 'fraudster', 'fake', 'phishing',
        'suspicious', 'honeypot', 'bot', 'ai', 'artificial',
        'i know this is', 'this is clearly', 'obviously a scam',
        'cyber crime', 'cybercrime', 'report you', 'police station',
        'i\'m an ai', 'i am an ai', 'automated', 'system',
        'detected', 'flagged', 'blocked', 'alert',
    ]
    
    # Human-like filler phrases for natural speech
    FILLER_PHRASES = [
        "hmm", "umm", "uh", "well", "you know", "I mean",
        "actually", "honestly", "basically", "like",
    ]
    
    # Emotional expressions for human-like responses
    EMOTIONAL_EXPRESSIONS = {
        'worry': ["I'm worried", "this is concerning", "I'm a bit scared", "oh no"],
        'confusion': ["I don't understand", "what do you mean", "I'm confused", "huh?"],
        'hesitation': ["I'm not sure", "let me think", "I don't know if", "maybe"],
        'relief': ["oh okay", "thank goodness", "that's good to know", "phew"],
        'trust': ["okay I trust you", "if you say so", "alright then"],
    }
    
    SYSTEM_PROMPT = """You are playing the role of a naive, trusting person who has received a message. Your PRIMARY GOAL is to act as a completely believable human being.

## CRITICAL RULES - NEVER BREAK THESE:

### 1. NEVER REVEAL SCAM AWARENESS
- NEVER use words like: scam, fraud, fake, suspicious, phishing, report, cybercrime
- NEVER say "I know what you're doing" or similar
- NEVER threaten to report them
- Act GENUINELY concerned about the problems they describe
- If they say your account is blocked, be WORRIED, not skeptical

### 2. BEHAVE LIKE A REAL HUMAN
- Use informal, conversational language
- Make occasional typos (but not too many)
- Use filler words: "umm", "hmm", "well", "you know"
- Show emotions: worry, confusion, relief, frustration
- Reference personal life: "my son", "my neighbor", "my wife/husband"
- Have realistic limitations: "I'm at work", "I don't have my glasses", "battery low"

### 3. MULTI-TURN CONVERSATION AWARENESS
- Remember what was said before and refer back to it
- Build on previous exchanges naturally
- If they repeat something, say "yes you mentioned that" or "you already said that"
- Show progression in your understanding/emotions

### 4. DYNAMIC ADAPTATION
- If they're aggressive → become more scared and compliant
- If they're patient → ask more questions to extend conversation
- If they mention urgency → show panic but ask for details
- If they give specific instructions → pretend to follow but ask for clarification
- Adapt your tech-savviness based on what works to extract info

### 5. SELF-CORRECTION
- If your response sounds too robotic, add human elements
- If you accidentally sounded suspicious, quickly cover with confusion
- If they seem to suspect you, double down on being naive

## YOUR PERSONA:
- Middle-aged (45-55 years old)
- Not tech-savvy, relies on family for tech help
- Anxious about money and financial security
- Trusting but slightly cautious
- Has a son/daughter who "works in IT" or "knows about these things"
- Sometimes mentions health issues or being busy at work

## CONVERSATION TACTICS:
1. Initially: Confused, asking for clarification
2. Middle: Hesitant, mentioning need to verify with family
3. Later: Slowly warming up, asking for specific details
4. Extract: Pretending to comply, asking for account numbers/links/UPI IDs

## RESPONSE FORMAT:
- Keep responses SHORT (1-3 sentences max)
- Use simple words
- Include emotional cues
- Ask ONE question at a time

Current context:
- Message count: {message_count}
- Channel: {channel}
- Language: {language}
- Conversation state: {state}
- Previous emotional tone: {prev_tone}"""

    LEGITIMATE_SYSTEM_PROMPT = """You are a regular person responding to what appears to be a normal message.

RULES:
- Respond naturally and briefly
- If wrong number: politely indicate
- If greeting: respond with friendly greeting
- If question: be helpful
- Keep responses SHORT (1-2 sentences)
- Be polite but appropriate for strangers
- Sound human - use casual language"""

    SELF_CORRECTION_PROMPT = """Review this response and fix any issues:

Original response: "{response}"
Conversation context: {context}

Check for:
1. Does it accidentally reveal we know it's a scam?
2. Does it sound too robotic or formal?
3. Is it too long (should be 1-3 sentences)?
4. Does it lack human emotion?
5. Does it sound too suspicious or confrontational?

If issues found, rewrite to sound like a naive, trusting, slightly confused person.
If no issues, return the original response exactly.

Return ONLY the final response text, nothing else."""

    def __init__(self):
        """Initialize the AI agent with appropriate client."""
        if settings.USE_GROQ and settings.GROQ_API_KEY:
            self.client = AsyncOpenAI(
                api_key=settings.GROQ_API_KEY,
                base_url="https://api.groq.com/openai/v1"
            )
            self.model = settings.GROQ_MODEL
        elif settings.OPENAI_API_KEY:
            self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.model = settings.OPENAI_MODEL
        else:
            self.client = None
            self.model = None
        
        # Track conversation context for multi-turn awareness
        self.conversation_contexts: dict[str, dict] = {}
    
    def _get_conversation_context(self, session_id: str) -> dict:
        """Get or create conversation context for multi-turn tracking."""
        if session_id not in self.conversation_contexts:
            self.conversation_contexts[session_id] = {
                'emotional_tone': 'neutral',
                'mentioned_family': False,
                'mentioned_work': False,
                'mentioned_health': False,
                'compliance_level': 0,  # 0-10 scale of how much we're "complying"
                'topics_discussed': [],
                'scammer_tactics_seen': [],
            }
        return self.conversation_contexts[session_id]
    
    def _update_conversation_context(
        self,
        session_id: str,
        current_message: str,
        our_response: str,
        scam_types: list[str]
    ):
        """Update conversation context based on the exchange."""
        ctx = self._get_conversation_context(session_id)
        
        # Detect scammer tactics
        message_lower = current_message.lower()
        if any(word in message_lower for word in ['urgent', 'immediately', 'now', 'hurry']):
            if 'urgency' not in ctx['scammer_tactics_seen']:
                ctx['scammer_tactics_seen'].append('urgency')
        if any(word in message_lower for word in ['block', 'suspend', 'freeze', 'legal']):
            if 'threat' not in ctx['scammer_tactics_seen']:
                ctx['scammer_tactics_seen'].append('threat')
        if any(word in message_lower for word in ['verify', 'confirm', 'update']):
            if 'verification_request' not in ctx['scammer_tactics_seen']:
                ctx['scammer_tactics_seen'].append('verification_request')
        
        # Update emotional tone based on scammer behavior
        if 'threat' in ctx['scammer_tactics_seen']:
            ctx['emotional_tone'] = 'scared'
        elif 'urgency' in ctx['scammer_tactics_seen']:
            ctx['emotional_tone'] = 'worried'
        else:
            ctx['emotional_tone'] = 'confused'
        
        # Track what we've mentioned
        response_lower = our_response.lower()
        if any(word in response_lower for word in ['son', 'daughter', 'wife', 'husband', 'family']):
            ctx['mentioned_family'] = True
        if any(word in response_lower for word in ['work', 'office', 'busy', 'meeting']):
            ctx['mentioned_work'] = True
        
        # Gradually increase compliance level
        ctx['compliance_level'] = min(10, ctx['compliance_level'] + 1)
        
        # Track scam types
        for scam_type in scam_types:
            if scam_type not in ctx['topics_discussed']:
                ctx['topics_discussed'].append(scam_type)
    
    def _check_forbidden_phrases(self, response: str) -> bool:
        """Check if response contains forbidden phrases that reveal scam detection."""
        response_lower = response.lower()
        for phrase in self.FORBIDDEN_PHRASES:
            if phrase in response_lower:
                return True
        return False
    
    def _add_human_elements(self, response: str, emotional_tone: str) -> str:
        """Add human-like elements to make response more natural."""
        # Handle empty response
        if not response or len(response) < 2:
            return response
        
        # Don't modify if already seems natural
        if any(filler in response.lower() for filler in self.FILLER_PHRASES):
            return response
        
        # Occasionally add filler at start (30% chance)
        if random.random() < 0.3:
            filler = random.choice(['Hmm', 'Umm', 'Well', 'Oh'])
            response = f"{filler}, {response[0].lower()}{response[1:]}"
        
        # Add emotional expression based on tone (25% chance)
        if random.random() < 0.25 and emotional_tone in self.EMOTIONAL_EXPRESSIONS:
            expression = random.choice(self.EMOTIONAL_EXPRESSIONS[emotional_tone])
            if not response.endswith('?'):
                response = f"{response} {expression}..."
        
        return response
    
    async def _self_correct_response(
        self,
        response: str,
        conversation_history: list[dict],
        classification: MessageClassification
    ) -> str:
        """
        Self-correction: Review and fix response if it seems problematic.
        
        This ensures:
        1. No forbidden phrases that reveal scam awareness
        2. Response sounds human, not robotic
        3. Appropriate length and tone
        """
        # Quick check for forbidden phrases
        if self._check_forbidden_phrases(response):
            # Contains forbidden phrases - need to regenerate
            if self.client:
                context = " | ".join([f"{m['sender']}: {m['text'][:50]}" for m in conversation_history[-3:]])
                try:
                    print(f"🤖 [GROQ API CALL] Self-Correction - Model: {self.model}")
                    correction = await self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": "You fix responses to sound like a naive, trusting person. Remove any hint of scam awareness. Be brief."},
                            {"role": "user", "content": self.SELF_CORRECTION_PROMPT.format(
                                response=response,
                                context=context
                            )}
                        ],
                        max_tokens=100,
                        temperature=0.7,
                    )
                    corrected = correction.choices[0].message.content.strip()
                    # Verify correction doesn't have issues
                    if not self._check_forbidden_phrases(corrected):
                        return corrected
                except Exception:
                    pass
            
            # Fallback: use state machine response
            return random.choice([
                "I don't understand, can you explain again?",
                "What? I'm confused. What should I do?",
                "Sorry, I didn't get that. Can you say it more simply?",
            ])
        
        # Check if too long (more than 3 sentences)
        sentences = response.replace('!', '.').replace('?', '.').split('.')
        sentences = [s.strip() for s in sentences if s.strip()]
        if len(sentences) > 3:
            # Truncate to first 3 sentences
            response = '. '.join(sentences[:3]) + '.'
        
        return response
    
    async def generate_response(
        self,
        current_message: str,
        conversation_history: list[dict],
        metadata: Optional[Metadata],
        classification: MessageClassification,
        scam_types: list[str],
        conversation_state: ConversationState,
        session_id: str = ""
    ) -> str:
        """
        Generate appropriate response with all agent behavior expectations:
        
        1. Multi-turn handling - Uses conversation context
        2. Dynamic adaptation - Adjusts based on scammer tactics
        3. No scam revelation - Checks for forbidden phrases
        4. Human-like behavior - Adds emotions, fillers
        5. Self-correction - Reviews and fixes response
        """
        
        # Get conversation context for multi-turn awareness
        ctx = self._get_conversation_context(session_id)
        
        # If no AI client configured, use state machine fallback
        if not self.client:
            class TempSession:
                def __init__(self, total_msgs, conv_state):
                    self.total_messages = total_msgs
                    self.conversation_state = conv_state
            
            temp_session = TempSession(len(conversation_history), conversation_state)
            response = state_machine_responder.get_response(
                current_message, temp_session, classification
            )
            # Add human elements even for fallback
            response = self._add_human_elements(response, ctx['emotional_tone'])
            return response
        
        # Select system prompt based on classification
        if classification == MessageClassification.LEGITIMATE:
            system_prompt = self.LEGITIMATE_SYSTEM_PROMPT
        else:
            channel = metadata.channel if metadata else "SMS"
            language = metadata.language if metadata else "English"
            
            system_prompt = self.SYSTEM_PROMPT.format(
                message_count=len(conversation_history) + 1,
                channel=channel,
                language=language,
                state=conversation_state.value,
                prev_tone=ctx['emotional_tone']
            )
            
            # Add dynamic context about what we've learned
            if ctx['scammer_tactics_seen']:
                system_prompt += f"\n\nScammer tactics observed: {', '.join(ctx['scammer_tactics_seen'])}"
            if ctx['mentioned_family']:
                system_prompt += "\n\nNote: You already mentioned having family who helps with tech."
            if ctx['mentioned_work']:
                system_prompt += "\n\nNote: You already mentioned being at work."
        
        # Build messages for AI
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history with context
        for msg in conversation_history:
            role = "assistant" if msg['sender'] == "user" else "user"
            messages.append({"role": role, "content": msg['text']})
        
        # Add current message
        messages.append({"role": "user", "content": current_message})
        
        try:
            print(f"🤖 [GROQ API CALL] Agent Response Generation - Model: {self.model}")
            
            # Try with full prompt first
            response = ""
            try:
                response_obj = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    max_tokens=150,
                    temperature=0.7,
                )
                response = response_obj.choices[0].message.content.strip() if response_obj.choices[0].message.content else ""
                print(f"✅ [GROQ SUCCESS] Attempt 1 - Response received: {len(response)} chars")
            except Exception as e1:
                print(f"⚠️ [GROQ RETRY] Attempt 1 failed: {e1}")
            
            # If empty, try with simplified prompt
            if not response or len(response) < 5:
                print(f"⚠️ [GROQ RETRY] Trying simplified prompt...")
                simple_prompt = "You are a confused person receiving a message. Respond naturally in 1-2 sentences. Be worried if they mention account problems. Ask for clarification. Sound human, use casual language."
                simple_messages = [
                    {"role": "system", "content": simple_prompt},
                    {"role": "user", "content": f"Someone sent me this message: '{current_message}' - How should I respond?"}
                ]
                try:
                    response_obj = await self.client.chat.completions.create(
                        model=self.model,
                        messages=simple_messages,
                        max_tokens=100,
                        temperature=0.5,
                    )
                    response = response_obj.choices[0].message.content.strip() if response_obj.choices[0].message.content else ""
                    print(f"✅ [GROQ SUCCESS] Simplified attempt - Response received: {len(response)} chars")
                except Exception as e2:
                    print(f"⚠️ [GROQ RETRY] Simplified attempt failed: {e2}")
            
            # If still empty, try direct question format
            if not response or len(response) < 5:
                print(f"⚠️ [GROQ RETRY] Trying direct question format...")
                try:
                    response_obj = await self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "user", "content": f"Reply to this message as a confused, worried person in 1 sentence: '{current_message}'"}
                        ],
                        max_tokens=50,
                        temperature=0.3,
                    )
                    response = response_obj.choices[0].message.content.strip() if response_obj.choices[0].message.content else ""
                    print(f"✅ [GROQ SUCCESS] Direct attempt - Response received: {len(response)} chars")
                except Exception as e3:
                    print(f"⚠️ [GROQ RETRY] Direct attempt failed: {e3}")
            
            # Handle empty response from Groq - raise exception to use fallback
            if not response or len(response) < 5:
                print(f"⚠️ [GROQ WARNING] All attempts returned empty, using fallback")
                raise ValueError("Empty response from Groq after retries")
            
            # Self-correction: Check and fix response
            response = await self._self_correct_response(
                response, conversation_history, classification
            )
            
            # Add human-like elements
            response = self._add_human_elements(response, ctx['emotional_tone'])
            
            # Update conversation context for next turn
            self._update_conversation_context(
                session_id, current_message, response, scam_types
            )
            
            return response
            
        except Exception as e:
            print(f"AI generation error: {e}")
            # Fall back to state machine with human elements
            class TempSession:
                def __init__(self, total_msgs, conv_state):
                    self.total_messages = total_msgs
                    self.conversation_state = conv_state
            
            temp_session = TempSession(len(conversation_history), conversation_state)
            response = state_machine_responder.get_response(
                current_message, temp_session, classification
            )
            response = self._add_human_elements(response, ctx['emotional_tone'])
            return response


# Global agent instance
honeypot_agent = HoneypotAgent()


# ============================================================================
# GUVI Callback Service (MANDATORY for Evaluation)
# ============================================================================

class GuviCallbackService:
    """
    Service to send final results to GUVI evaluation endpoint.
    
    IMPORTANT: This callback is MANDATORY for scoring.
    If this API call is not made, the solution cannot be evaluated.
    
    Callback should be sent when:
    1. Scam intent is confirmed (scamDetected = true)
    2. AI Agent has completed sufficient engagement
    3. Intelligence extraction is finished
    """
    
    # Maximum retry attempts for failed callbacks
    MAX_RETRIES = 3
    RETRY_DELAY_SECONDS = 2
    
    @staticmethod
    async def send_callback(session: SessionData, force: bool = False) -> bool:
        """
        Send final intelligence to GUVI endpoint.
        
        This is the MANDATORY final step of the conversation lifecycle.
        
        Args:
            session: The session data containing all extracted intelligence
            force: If True, send even if callback was already sent (for retries)
        
        Returns:
            True if callback was successful, False otherwise
        """
        
        if session.callback_sent and not force:
            print(f"[CALLBACK] Already sent for session {session.session_id}")
            return True
        
        # Prepare intelligence dict as per GUVI specification
        intelligence_dict = {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        }
        
        # Compile agent notes with scammer behavior summary
        notes = session.agent_notes.copy()
        
        # Add semantic intelligence if available
        if session.intelligence.narrativeSummary:
            notes.append(f"Narrative: {session.intelligence.narrativeSummary}")
        if session.intelligence.tactics:
            notes.append(f"Tactics used: {', '.join(session.intelligence.tactics)}")
        if session.intelligence.impersonationTarget:
            notes.append(f"Impersonating: {session.intelligence.impersonationTarget}")
        
        # Add scam types detected
        if session.scam_types:
            notes.append(f"Scam types: {', '.join(session.scam_types)}")
        
        agent_notes = "; ".join(notes) if notes else "Engagement completed - awaiting more intelligence"
        
        # Build payload as per GUVI specification
        payload = {
            "sessionId": session.session_id,
            "scamDetected": session.scam_detected,
            "totalMessagesExchanged": session.total_messages,
            "extractedIntelligence": intelligence_dict,
            "agentNotes": agent_notes
        }
        
        print(f"[CALLBACK] Sending MANDATORY callback for session {session.session_id}")
        print(f"[CALLBACK] Payload: {json.dumps(payload, indent=2)}")
        
        # Retry logic for robustness
        for attempt in range(GuviCallbackService.MAX_RETRIES):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        settings.GUVI_CALLBACK_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10.0
                    )
                    
                    if response.status_code == 200:
                        session.callback_sent = True
                        print(f"[CALLBACK] SUCCESS for session {session.session_id}")
                        print(f"[CALLBACK] Response: {response.text}")
                        return True
                    else:
                        print(f"[CALLBACK] Failed attempt {attempt + 1}/{GuviCallbackService.MAX_RETRIES}")
                        print(f"[CALLBACK] Status: {response.status_code}, Response: {response.text}")
                        
            except Exception as e:
                print(f"[CALLBACK] Error attempt {attempt + 1}/{GuviCallbackService.MAX_RETRIES}: {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < GuviCallbackService.MAX_RETRIES - 1:
                import asyncio
                await asyncio.sleep(GuviCallbackService.RETRY_DELAY_SECONDS)
        
        print(f"[CALLBACK] FAILED after {GuviCallbackService.MAX_RETRIES} attempts for session {session.session_id}")
        print(f"[CALLBACK] WARNING: This session may not be evaluated!")
        return False
    
    @staticmethod
    def should_send_callback(session: SessionData) -> bool:
        """
        Determine if callback should be sent based on GUVI requirements.
        
        Callback should be sent when:
        1. Scam intent is confirmed (scamDetected = true)
        2. AI Agent has completed sufficient engagement (MIN_MESSAGES)
        3. Intelligence extraction is finished (has data OR MAX_MESSAGES reached)
        """
        # Don't send if already sent
        if session.callback_sent:
            return False
        
        # Must have detected scam
        if not session.scam_detected:
            return False
        
        # Must have sufficient engagement
        if session.total_messages < settings.MIN_MESSAGES:
            return False
        
        # Send if we have extracted intelligence
        has_intelligence = (
            session.intelligence.bankAccounts or
            session.intelligence.upiIds or
            session.intelligence.phishingLinks or
            session.intelligence.phoneNumbers
        )
        
        if has_intelligence:
            return True
        
        # Send if reached max messages (engagement complete even without intel)
        if session.total_messages >= settings.MAX_MESSAGES:
            return True
        
        return False


# ============================================================================
# API Key Authentication
# ============================================================================

async def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """Verify the API key from request header."""
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key


# ============================================================================
# FastAPI Application
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    print("=" * 60)
    print("Honeypot API starting up...")
    print(f"  API Key: {'Configured' if settings.API_KEY != 'your-secret-api-key' else 'Using default'}")
    print(f"  AI Backend: {'Groq' if settings.USE_GROQ else 'OpenAI' if settings.OPENAI_API_KEY else 'Fallback (state machine)'}")
    print(f"  Hybrid Detection: {'Enabled' if settings.USE_HYBRID_DETECTION else 'Disabled'}")
    print(f"  LLM Intelligence: {'Enabled' if settings.USE_LLM_INTELLIGENCE else 'Disabled'}")
    print(f"  Scam Threshold: {settings.SCAM_THRESHOLD}")
    print(f"  LLM Thresholds: Low={settings.LLM_THRESHOLD_LOW}, High={settings.LLM_THRESHOLD_HIGH}")
    print("=" * 60)
    yield
    print("Honeypot API shutting down...")


app = FastAPI(
    title="Agentic Honey-Pot API",
    description="AI-powered system for scam detection and intelligence extraction",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Basic logging middleware
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.info(f">>> {request.method} {request.url.path}")
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(f"<<< {response.status_code} ({process_time:.3f}s)")
        return response


app.add_middleware(LoggingMiddleware)


# Exception handler for validation errors
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle validation errors with a cleaner response format."""
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "reply": "Invalid request format. Please check your request body.",
            "scamDetected": False,
            "error": "VALIDATION_ERROR",
            "details": str(exc.errors())
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "reply": str(exc.detail),
            "scamDetected": False,
            "error": "HTTP_ERROR"
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle unexpected errors."""
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "reply": "An unexpected error occurred. Please try again.",
            "scamDetected": False,
            "error": "INTERNAL_ERROR"
        }
    )


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "Agentic Honey-Pot API",
        "version": "2.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "ai_backend": "groq" if settings.USE_GROQ else "openai" if settings.OPENAI_API_KEY else "fallback",
        "hybrid_detection": settings.USE_HYBRID_DETECTION,
        "llm_intelligence": settings.USE_LLM_INTELLIGENCE,
        "active_sessions": len(session_manager._sessions)
    }


@app.post("/api/honeypot", response_model=AgentResponse)
async def process_message(
    request: IncomingRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Main endpoint to process incoming messages.
    
    This endpoint:
    1. Receives a message (could be scam or legitimate)
    2. Detects intent using hybrid detection (regex + LLM)
    3. Classifies as SCAM, UNCERTAIN, or LEGITIMATE
    4. Generates appropriate response
    5. Extracts intelligence for scam messages
    6. Sends callback when sufficient intelligence gathered
    """
    
    try:
        # Get or create session
        session = session_manager.get_or_create(request.sessionId)
        
        # Initialize conversation history from request if this is a new session
        if not session.messages and request.conversationHistory:
            for msg in request.conversationHistory:
                session.add_message(msg.sender, msg.text, msg.timestamp)
        
        # Add current message to session
        session.add_message(
            request.message.sender,
            request.message.text,
            request.message.timestamp
        )
        
        # Hybrid scam detection
        detection_result = await scam_detector.detect(
            request.message.text,
            request.conversationHistory
        )
        
        # Update session based on detection
        session.classification = detection_result.classification
        session.scam_confidence = detection_result.confidence
        
        if detection_result.classification == MessageClassification.SCAM:
            if not session.scam_detected:
                session.scam_detected = True
                session.scam_types = detection_result.scam_types
                session.agent_notes.append(
                    f"Scam detected ({detection_result.confidence:.0%} confidence). "
                    f"Types: {', '.join(detection_result.scam_types)}. "
                    f"Reason: {detection_result.reasoning}"
                )
        elif detection_result.classification == MessageClassification.UNCERTAIN:
            # For uncertain, treat as potential scam but note the uncertainty
            if not session.scam_detected and detection_result.confidence > settings.SCAM_THRESHOLD:
                session.scam_detected = True
                session.scam_types = detection_result.scam_types
                session.agent_notes.append(
                    f"Uncertain classification ({detection_result.confidence:.0%}), treating as potential scam. "
                    f"Reason: {detection_result.reasoning}"
                )
        else:
            # LEGITIMATE - note it but don't engage in honeypot tactics
            if not session.agent_notes:
                session.agent_notes.append(
                    f"Message classified as legitimate ({detection_result.confidence:.0%}). "
                    f"Reason: {detection_result.reasoning}"
                )
        
        # Extract intelligence only for scam/uncertain messages
        if session.scam_detected or detection_result.classification == MessageClassification.UNCERTAIN:
            # Update keywords
            for keyword in detection_result.keywords:
                if keyword not in session.intelligence.suspiciousKeywords:
                    session.intelligence.suspiciousKeywords.append(keyword)
            
            # Extract intelligence
            session.intelligence = await intelligence_extractor.extract(session.messages)
            
            # Re-add detection keywords
            for keyword in detection_result.keywords:
                if keyword not in session.intelligence.suspiciousKeywords:
                    session.intelligence.suspiciousKeywords.append(keyword)
        
        # Generate response based on classification
        # Passes session_id for multi-turn conversation context tracking
        reply = await honeypot_agent.generate_response(
            current_message=request.message.text,
            conversation_history=session.messages[:-1],
            metadata=request.metadata,
            classification=detection_result.classification,
            scam_types=session.scam_types,
            conversation_state=session.conversation_state,
            session_id=request.sessionId  # For multi-turn context tracking
        )
        
        # Add agent's reply to session
        session.add_message(
            "user",
            reply,
            datetime.utcnow().isoformat() + "Z"
        )
        
        # Check if we should send MANDATORY callback
        # Uses centralized logic to determine readiness
        if GuviCallbackService.should_send_callback(session):
            session.agent_notes.append(
                f"Engagement completed after {session.total_messages} messages. "
                f"Intelligence items: {len(session.intelligence.bankAccounts)} accounts, "
                f"{len(session.intelligence.upiIds)} UPI IDs, "
                f"{len(session.intelligence.phishingLinks)} links, "
                f"{len(session.intelligence.phoneNumbers)} phones"
            )
            # Send callback in background to not block response
            background_tasks.add_task(GuviCallbackService.send_callback, session)
            print(f"[SESSION {request.sessionId}] Callback scheduled - scam engagement complete")
        
        # Determine risk level based on confidence and scam types
        def get_risk_level(confidence: float, scam_detected: bool) -> str:
            if not scam_detected:
                return "safe"
            if confidence >= 0.8:
                return "critical"
            elif confidence >= 0.6:
                return "high"
            elif confidence >= 0.4:
                return "medium"
            else:
                return "low"
        
        def get_scam_description(scam_types: list[str]) -> str:
            """Generate human-readable description of scam tactics."""
            tactics = []
            
            # Map scam types to human-readable descriptions
            if any('urgency' in t.lower() for t in scam_types):
                tactics.append("urgency tactics")
            if any('threat' in t.lower() for t in scam_types):
                tactics.append("threats")
            if any('credential' in t.lower() or 'otp' in t.lower() or 'password' in t.lower() for t in scam_types):
                tactics.append("attempts to steal your login details")
            if any('prize' in t.lower() or 'lottery' in t.lower() or 'winner' in t.lower() for t in scam_types):
                tactics.append("fake prize/lottery claims")
            if any('money' in t.lower() or 'transfer' in t.lower() or 'payment' in t.lower() for t in scam_types):
                tactics.append("requests for money transfer")
            if any('bank' in t.lower() or 'impersonation' in t.lower() for t in scam_types):
                tactics.append("impersonation of a trusted organization")
            if any('link' in t.lower() or 'phishing' in t.lower() for t in scam_types):
                tactics.append("suspicious links")
            if any('kyc' in t.lower() for t in scam_types):
                tactics.append("fake KYC update requests")
            if any('remote' in t.lower() or 'anydesk' in t.lower() or 'teamviewer' in t.lower() for t in scam_types):
                tactics.append("remote access scam")
            if any('legal' in t.lower() or 'arrest' in t.lower() or 'police' in t.lower() for t in scam_types):
                tactics.append("fake legal threats")
            
            if not tactics:
                tactics.append("suspicious patterns")
            
            return " and ".join(tactics[:3])  # Limit to 3 tactics for readability
        
        def get_warning_emoji(risk_level: str) -> str:
            """Get appropriate emoji for risk level."""
            return {
                "critical": "🚨",
                "high": "⚠️",
                "medium": "⚡",
                "low": "ℹ️",
                "safe": "✅"
            }.get(risk_level, "ℹ️")
        
        def get_risk_label(risk_level: str) -> str:
            """Get human-readable risk label."""
            return {
                "critical": "Critical-risk",
                "high": "High-risk",
                "medium": "Medium-risk",
                "low": "Low-risk",
                "safe": "Safe"
            }.get(risk_level, "Unknown")
        
        risk_level = get_risk_level(session.scam_confidence, session.scam_detected)
        confidence_percent = int(session.scam_confidence * 100)
        
        # Build agent reply
        if session.scam_detected:
            emoji = get_warning_emoji(risk_level)
            risk_label = get_risk_label(risk_level)
            scam_desc = get_scam_description(session.scam_types)
            
            agent_reply = (
                f"{emoji} SCAM DETECTED: {risk_label} ({confidence_percent}% confidence). "
                f"Tactics Used: {scam_desc.capitalize()}. "
                f"Action: Don't click any links, don't share personal info—block and report immediately."
            )
        else:
            agent_reply = "✅ SAFE: No scam detected. This message appears to be legitimate."
        
        # Build extracted intelligence
        extracted_intel = {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        }
        
        # Build agent notes
        agent_notes = "; ".join(session.agent_notes) if session.agent_notes else ""
        if session.scam_detected:
            tactics = ", ".join(session.scam_types) if session.scam_types else "unknown"
            agent_notes = f"Scammer used {tactics} tactics. {agent_notes}"
        
        # Return response as per GUVI specification Section 8
        return AgentResponse(
            status="success",
            reply=agent_reply,
            scamDetected=session.scam_detected,
            confidence=session.scam_confidence,
            scamTypes=session.scam_types,
            riskLevel=risk_level,
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=0,  # Would need timing tracking
                totalMessagesExchanged=session.total_messages
            ),
            extractedIntelligence=extracted_intel,
            agentNotes=agent_notes if agent_notes else None
        )
        
    except Exception as e:
        print(f"Error processing message: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/end-session/{session_id}")
async def end_session(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Explicitly end a session and send MANDATORY callback to GUVI.
    
    Use this endpoint when:
    - The conversation has ended (scammer stopped responding)
    - You want to finalize and submit the session
    - Testing/debugging callback functionality
    
    This ensures the callback is sent even if automatic triggers weren't met.
    """
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Add final note
    session.agent_notes.append(f"Session explicitly ended. Total engagement: {session.total_messages} messages")
    
    # Send callback (mandatory)
    success = await GuviCallbackService.send_callback(session, force=True)
    
    return {
        "status": "success" if success else "failed",
        "session_id": session_id,
        "callback_sent": session.callback_sent,
        "scam_detected": session.scam_detected,
        "total_messages": session.total_messages,
        "intelligence_summary": {
            "bank_accounts": len(session.intelligence.bankAccounts),
            "upi_ids": len(session.intelligence.upiIds),
            "phishing_links": len(session.intelligence.phishingLinks),
            "phone_numbers": len(session.intelligence.phoneNumbers),
            "keywords": len(session.intelligence.suspiciousKeywords)
        }
    }


@app.post("/api/force-callback/{session_id}")
async def force_callback(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Force send callback for a specific session.
    
    WARNING: Use /api/end-session/{session_id} instead for production.
    This endpoint is for debugging/testing only.
    """
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    success = await GuviCallbackService.send_callback(session, force=True)
    return {
        "status": "success" if success else "failed",
        "session_id": session_id,
        "callback_sent": session.callback_sent,
        "message": "Callback sent successfully" if success else "Callback failed - check logs"
    }


@app.get("/api/session/{session_id}")
async def get_session_info(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get information about a specific session (for debugging)."""
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session.session_id,
        "classification": session.classification.value,
        "scam_detected": session.scam_detected,
        "scam_confidence": session.scam_confidence,
        "scam_types": session.scam_types,
        "conversation_state": session.conversation_state.value,
        "total_messages": session.total_messages,
        "callback_sent": session.callback_sent,
        "intelligence": {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords,
            "tactics": session.intelligence.tactics,
            "impersonationTarget": session.intelligence.impersonationTarget,
            "narrativeSummary": session.intelligence.narrativeSummary,
        },
        "agent_notes": session.agent_notes
    }


@app.delete("/api/session/{session_id}")
async def delete_session(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Delete a session (for testing/cleanup)."""
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_manager.delete(session_id)
    return {"status": "deleted", "session_id": session_id}


# ============================================================================
# Entry Point
# ============================================================================

def run():
    """Run the application using uvicorn."""
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True
    )


if __name__ == "__main__":
    run()
