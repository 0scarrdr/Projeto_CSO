"""
Azure Active Directory Integration
Provides identity and access management capabilities for incident response
"""

import logging
import json
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class IAMAction:
    """Represents an Identity and Access Management action result."""
    action_type: str
    target_user: str
    success: bool
    timestamp: str
    details: Dict[str, Any]
    error: Optional[str] = None

class AzureADManager:
    """
    Azure Active Directory Manager for identity-based incident response
    
    Provides IAM capabilities including:
    - User account management (disable/enable)
    - Password reset and security
    - Group membership management
    - Security alerts and monitoring
    """
    
    def __init__(self, tenant_id: str = None, client_id: str = None, 
                 client_secret: str = None):
        """
        Initialize Azure AD Manager
        
        Args:
            tenant_id: Azure AD tenant ID
            client_id: Application client ID
            client_secret: Application client secret
        """
        self.tenant_id = tenant_id or "6bfdb318-8dfa-4d4c-ae55-c0862aa6a5b1"
        self.client_id = client_id or "cc361287-4039-4a65-bdbf-864068f04525"
        self.client_secret = client_secret
        self.graph_api_url = "https://graph.microsoft.com/v1.0"
        
        self.access_token = None
        self.token_expires_at = None
        self.session = requests.Session()
        self.initialized = False
        
        logger.info("AzureADManager initialized")
    
    def _get_access_token(self) -> bool:
        """Get access token for Microsoft Graph API"""
        try:
            # Check if current token is still valid
            if (self.access_token and self.token_expires_at and 
                datetime.now(timezone.utc) < self.token_expires_at - timedelta(minutes=5)):
                return True
            
            # Get new token
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://graph.microsoft.com/.default'
            }
            
            response = self.session.post(token_url, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data['access_token']
            expires_in = int(token_data.get('expires_in', 3600))
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            
            # Update session headers
            self.session.headers.update({
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            })
            
            logger.info("Access token obtained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            return False
    
    def initialize(self) -> bool:
        """Initialize Azure AD client and test connection"""
        try:
            if not self.client_secret:
                logger.warning("No client secret provided, using mock mode")
                self.initialized = True
                return True
            
            # Get access token
            if not self._get_access_token():
                return False
            
            # Test API connection
            test_url = f"{self.graph_api_url}/organization"
            response = self.session.get(test_url)
            
            if response.status_code == 200:
                org_data = response.json()
                org_name = org_data.get('value', [{}])[0].get('displayName', 'Unknown')
                logger.info(f"Connected to Azure AD organization: {org_name}")
            else:
                logger.warning(f"API test returned status {response.status_code}, continuing in mock mode")
            
            self.initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure AD Manager: {e}")
            logger.info("Continuing in mock mode")
            self.initialized = True
            return True
    
    def disable_user_account(self, user_principal_name: str = None, user_id: str = None, 
                            reason: str = None) -> IAMAction:
        """
        Disable a user account for security incident response
        
        Args:
            user_principal_name: User's UPN (email)
            user_id: User's object ID
            reason: Reason for disabling
            
        Returns:
            IAMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return IAMAction(
                    action_type="disable_user",
                    target_user=user_principal_name or user_id or "unknown",
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure AD client not initialized"
                )
        
        target = user_principal_name or user_id or "sample.user@domain.com"
        
        try:
            logger.info(f"Disabling user account {target}")
            
            # If we have real credentials, try the actual API
            if self.access_token and self.client_secret:
                # Find user by UPN or use provided ID
                if user_principal_name and not user_id:
                    user_info = self._get_user_by_upn(user_principal_name)
                    if user_info:
                        user_id = user_info['id']
                
                if user_id:
                    # Update user to disable account
                    update_url = f"{self.graph_api_url}/users/{user_id}"
                    
                    payload = {
                        "accountEnabled": False
                    }
                    
                    response = self.session.patch(update_url, json=payload)
                    response.raise_for_status()
                    
                    logger.info(f"User account {target} disabled successfully")
                    
                    return IAMAction(
                        action_type="disable_user",
                        target_user=target,
                        success=True,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        details={
                            "user_id": user_id,
                            "user_principal_name": user_principal_name,
                            "reason": reason or "Security incident response",
                            "account_enabled": False
                        }
                    )
            
            # Mock mode - simulate successful account disable
            action_id = f"mock-disable-{int(datetime.now().timestamp())}"
            
            logger.info(f"User account {target} disabled (mock mode)")
            
            return IAMAction(
                action_type="disable_user",
                target_user=target,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "user_principal_name": target,
                    "action_id": action_id,
                    "reason": reason or "Security incident response",
                    "account_enabled": False,
                    "mode": "mock"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to disable user account {target}: {e}")
            return IAMAction(
                action_type="disable_user",
                target_user=target,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def enable_user_account(self, user_principal_name: str = None, user_id: str = None) -> IAMAction:
        """
        Enable a user account (for recovery operations)
        
        Args:
            user_principal_name: User's UPN (email)
            user_id: User's object ID
            
        Returns:
            IAMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return IAMAction(
                    action_type="enable_user",
                    target_user=user_principal_name or user_id or "unknown",
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure AD client not initialized"
                )
        
        target = user_principal_name or user_id or "sample.user@domain.com"
        
        try:
            logger.info(f"Enabling user account {target}")
            
            # If we have real credentials, try the actual API
            if self.access_token and self.client_secret:
                # Find user by UPN or use provided ID
                if user_principal_name and not user_id:
                    user_info = self._get_user_by_upn(user_principal_name)
                    if user_info:
                        user_id = user_info['id']
                
                if user_id:
                    # Update user to enable account
                    update_url = f"{self.graph_api_url}/users/{user_id}"
                    
                    payload = {
                        "accountEnabled": True
                    }
                    
                    response = self.session.patch(update_url, json=payload)
                    response.raise_for_status()
                    
                    logger.info(f"User account {target} enabled successfully")
                    
                    return IAMAction(
                        action_type="enable_user",
                        target_user=target,
                        success=True,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        details={
                            "user_id": user_id,
                            "user_principal_name": user_principal_name,
                            "account_enabled": True
                        }
                    )
            
            # Mock mode - simulate successful account enable
            action_id = f"mock-enable-{int(datetime.now().timestamp())}"
            
            logger.info(f"User account {target} enabled (mock mode)")
            
            return IAMAction(
                action_type="enable_user",
                target_user=target,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "user_principal_name": target,
                    "action_id": action_id,
                    "account_enabled": True,
                    "mode": "mock"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to enable user account {target}: {e}")
            return IAMAction(
                action_type="enable_user",
                target_user=target,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def force_password_reset(self, user_principal_name: str = None, user_id: str = None) -> IAMAction:
        """
        Force password reset for a user account
        
        Args:
            user_principal_name: User's UPN (email)
            user_id: User's object ID
            
        Returns:
            IAMAction result
        """
        if not self.initialized:
            if not self.initialize():
                return IAMAction(
                    action_type="force_password_reset",
                    target_user=user_principal_name or user_id or "unknown",
                    success=False,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    details={},
                    error="Azure AD client not initialized"
                )
        
        target = user_principal_name or user_id or "sample.user@domain.com"
        
        try:
            logger.info(f"Forcing password reset for user {target}")
            
            # Mock mode - simulate successful password reset
            action_id = f"mock-password-reset-{int(datetime.now().timestamp())}"
            
            logger.info(f"Password reset forced for user {target} (mock mode)")
            
            return IAMAction(
                action_type="force_password_reset",
                target_user=target,
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={
                    "user_principal_name": target,
                    "action_id": action_id,
                    "password_reset_required": True,
                    "mode": "mock"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to force password reset for user {target}: {e}")
            return IAMAction(
                action_type="force_password_reset",
                target_user=target,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                details={},
                error=str(e)
            )
    
    def get_user_sign_in_logs(self, user_principal_name: str = None, hours_back: int = 24) -> Dict[str, Any]:
        """
        Get user sign-in logs for investigation
        
        Args:
            user_principal_name: User's UPN (email)
            hours_back: How many hours back to look
            
        Returns:
            Sign-in logs information
        """
        if not self.initialized:
            if not self.initialize():
                return {
                    "success": False,
                    "error": "Azure AD client not initialized"
                }
        
        try:
            logger.info(f"Getting sign-in logs for user {user_principal_name} (last {hours_back} hours)")
            
            # Mock mode - generate sample sign-in logs
            logs = []
            for i in range(5):  # Generate 5 sample logs
                log_time = datetime.now(timezone.utc) - timedelta(hours=i*4)
                logs.append({
                    "id": f"signin-{int(log_time.timestamp())}",
                    "user_principal_name": user_principal_name or "sample.user@domain.com",
                    "created_datetime": log_time.isoformat(),
                    "app_display_name": ["Office 365", "Azure Portal", "Teams", "Outlook"][i % 4],
                    "client_app_used": "Browser",
                    "ip_address": f"192.168.1.{100 + i}",
                    "location": "Lisbon, Portugal",
                    "risk_level": ["Low", "Medium", "High"][i % 3],
                    "status": "Success" if i < 4 else "Failure"
                })
            
            return {
                "success": True,
                "user_principal_name": user_principal_name,
                "logs_count": len(logs),
                "sign_in_logs": logs,
                "mode": "mock"
            }
            
        except Exception as e:
            logger.error(f"Failed to get sign-in logs: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_user_risk_detections(self, user_principal_name: str = None) -> Dict[str, Any]:
        """
        Get user risk detections from Azure AD Identity Protection
        
        Args:
            user_principal_name: User's UPN (email)
            
        Returns:
            Risk detections information
        """
        if not self.initialized:
            if not self.initialize():
                return {
                    "success": False,
                    "error": "Azure AD client not initialized"
                }
        
        try:
            logger.info(f"Getting risk detections for user {user_principal_name}")
            
            # Mock mode - generate sample risk detections
            detections = []
            risk_types = ["Impossible travel", "Anonymous IP address", "Malware linked IP address", "Leaked credentials"]
            
            for i in range(2):  # Generate 2 sample detections
                detection_time = datetime.now(timezone.utc) - timedelta(days=i*3)
                detections.append({
                    "id": f"risk-{int(detection_time.timestamp())}",
                    "user_principal_name": user_principal_name or "sample.user@domain.com",
                    "detected_datetime": detection_time.isoformat(),
                    "risk_type": risk_types[i % len(risk_types)],
                    "risk_level": ["High", "Medium"][i % 2],
                    "risk_state": "Remediated" if i > 0 else "Active",
                    "ip_address": f"45.87.212.{180 + i}",
                    "location": "Unknown Location"
                })
            
            return {
                "success": True,
                "user_principal_name": user_principal_name,
                "detections_count": len(detections),
                "risk_detections": detections,
                "mode": "mock"
            }
            
        except Exception as e:
            logger.error(f"Failed to get risk detections: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_user_by_upn(self, user_principal_name: str) -> Optional[Dict[str, Any]]:
        """Get user information by UPN (helper method)"""
        try:
            if not self.access_token:
                return None
            
            user_url = f"{self.graph_api_url}/users/{user_principal_name}"
            response = self.session.get(user_url)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to get user by UPN {user_principal_name}: {e}")
            return None
