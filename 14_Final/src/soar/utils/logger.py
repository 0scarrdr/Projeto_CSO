"""
Logging Configuration
Comprehensive logging setup for the SOAR system with structured logging,
performance tracking, and security event logging
"""

import logging
import logging.handlers
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import traceback


class SOARFormatter(logging.Formatter):
    """Custom formatter for SOAR system logs with structured output"""
    
    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        
        # Base log structure
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add thread and process info if available
        if hasattr(record, 'thread') and record.thread:
            log_entry['thread_id'] = record.thread
        if hasattr(record, 'process') and record.process:
            log_entry['process_id'] = record.process
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add custom context if enabled
        if self.include_context and hasattr(record, 'context'):
            log_entry['context'] = record.context
        
        # Add incident ID if present
        if hasattr(record, 'incident_id'):
            log_entry['incident_id'] = record.incident_id
        
        # Add component info if present
        if hasattr(record, 'component'):
            log_entry['component'] = record.component
        
        # Add performance metrics if present
        if hasattr(record, 'duration'):
            log_entry['duration_ms'] = record.duration
        
        # Add security context if present
        if hasattr(record, 'security_event'):
            log_entry['security_event'] = record.security_event
        
        return json.dumps(log_entry, default=str)


class SecurityEventFilter(logging.Filter):
    """Filter to identify and mark security-related log events"""
    
    SECURITY_KEYWORDS = [
        'threat', 'attack', 'malware', 'intrusion', 'breach', 'vulnerability',
        'unauthorized', 'suspicious', 'phishing', 'ransomware', 'exploit',
        'compromise', 'escalation', 'lateral', 'exfiltration', 'ddos'
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Mark records as security events if they contain security keywords"""
        message_lower = record.getMessage().lower()
        
        # Check if message contains security keywords
        is_security_event = any(keyword in message_lower for keyword in self.SECURITY_KEYWORDS)
        
        if is_security_event:
            record.security_event = True
        
        return True  # Don't filter out any records


class PerformanceFilter(logging.Filter):
    """Filter to add performance context to log records"""
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add performance markers to relevant log records"""
        message = record.getMessage().lower()
        
        # Mark performance-related logs
        if any(term in message for term in ['processing time', 'duration', 'latency', 'performance', 'elapsed']):
            record.performance_log = True
        
        return True


class ContextLogger:
    """Context-aware logger that maintains request/incident context"""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self.context = {}
    
    def set_context(self, **context):
        """Set context for subsequent log messages"""
        self.context.update(context)
    
    def clear_context(self):
        """Clear all context"""
        self.context.clear()
    
    def _log_with_context(self, level: int, message: str, *args, **kwargs):
        """Log message with current context"""
        extra = kwargs.get('extra', {})
        extra['context'] = self.context.copy()
        kwargs['extra'] = extra
        
        self.logger.log(level, message, *args, **kwargs)
    
    def debug(self, message: str, *args, **kwargs):
        self._log_with_context(logging.DEBUG, message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        self._log_with_context(logging.INFO, message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        self._log_with_context(logging.WARNING, message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        self._log_with_context(logging.ERROR, message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        self._log_with_context(logging.CRITICAL, message, *args, **kwargs)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True,
    enable_security_logging: bool = True,
    enable_performance_logging: bool = True,
    log_format: str = "structured"  # "structured" or "standard"
) -> Dict[str, Any]:
    """
    Set up comprehensive logging for the SOAR system
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, uses default)
        max_file_size: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        enable_console: Whether to enable console logging
        enable_security_logging: Whether to enable security event logging
        enable_performance_logging: Whether to enable performance logging
        log_format: Log format type ("structured" or "standard")
    
    Returns:
        Dictionary with logging configuration details
    """
    
    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create logs directory if it doesn't exist
    if log_file is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / "soar_system.log"
    else:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    handlers = []
    
    # Set up formatters
    if log_format == "structured":
        formatter = SOARFormatter(include_context=True)
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s'
        )
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        
        # Add filters
        if enable_security_logging:
            console_handler.addFilter(SecurityEventFilter())
        if enable_performance_logging:
            console_handler.addFilter(PerformanceFilter())
        
        root_logger.addHandler(console_handler)
        handlers.append(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_file_size,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    
    # Add filters
    if enable_security_logging:
        file_handler.addFilter(SecurityEventFilter())
    if enable_performance_logging:
        file_handler.addFilter(PerformanceFilter())
    
    root_logger.addHandler(file_handler)
    handlers.append(file_handler)
    
    # Security events handler (separate file for security events)
    if enable_security_logging:
        security_log_file = log_file.parent / "security_events.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(formatter)
        
        # Filter to only log security events
        class SecurityOnlyFilter(logging.Filter):
            def filter(self, record):
                return hasattr(record, 'security_event') and record.security_event
        
        security_handler.addFilter(SecurityOnlyFilter())
        root_logger.addHandler(security_handler)
        handlers.append(security_handler)
    
    # Performance events handler (separate file for performance logs)
    if enable_performance_logging:
        perf_log_file = log_file.parent / "performance.log"
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.setFormatter(formatter)
        
        # Filter to only log performance events
        class PerformanceOnlyFilter(logging.Filter):
            def filter(self, record):
                return hasattr(record, 'performance_log') and record.performance_log
        
        perf_handler.addFilter(PerformanceOnlyFilter())
        root_logger.addHandler(perf_handler)
        handlers.append(perf_handler)
    
    # Configure specific logger levels for different components
    component_loggers = {
        'soar.detection': logging.INFO,
        'soar.analysis': logging.INFO,
        'soar.response': logging.INFO,
        'soar.prediction': logging.INFO,
        'soar.api': logging.INFO,
        'soar.core': logging.DEBUG,  # More detailed logging for core components
        'soar.utils': logging.WARNING,  # Less verbose for utilities
        'uvicorn': logging.WARNING,  # Reduce FastAPI verbosity
        'fastapi': logging.WARNING
    }
    
    for logger_name, level in component_loggers.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)
    
    # Log the logging configuration
    config_logger = logging.getLogger('soar.config')
    config_logger.info(
        "Logging system initialized",
        extra={
            'log_level': log_level,
            'log_file': str(log_file),
            'handlers_count': len(handlers),
            'security_logging': enable_security_logging,
            'performance_logging': enable_performance_logging,
            'log_format': log_format
        }
    )
    
    return {
        'log_level': log_level,
        'log_file': str(log_file),
        'handlers': [handler.__class__.__name__ for handler in handlers],
        'security_logging_enabled': enable_security_logging,
        'performance_logging_enabled': enable_performance_logging,
        'log_format': log_format,
        'file_rotation': {
            'max_size_mb': max_file_size / (1024 * 1024),
            'backup_count': backup_count
        }
    }


def get_context_logger(name: str) -> ContextLogger:
    """Get a context-aware logger for a specific component"""
    return ContextLogger(name)


def log_incident_event(
    logger: logging.Logger,
    incident_id: str,
    event_type: str,
    message: str,
    level: int = logging.INFO,
    **context
):
    """Log an incident-related event with proper context"""
    extra = {
        'incident_id': incident_id,
        'event_type': event_type,
        'component': 'incident_handler',
        'context': context
    }
    
    # Mark as security event if relevant
    if event_type in ['threat_detected', 'attack_blocked', 'breach_identified', 'response_executed']:
        extra['security_event'] = True
    
    logger.log(level, message, extra=extra)


def log_performance_event(
    logger: logging.Logger,
    operation: str,
    duration_ms: float,
    component: str,
    success: bool = True,
    **context
):
    """Log a performance-related event"""
    extra = {
        'component': component,
        'operation': operation,
        'duration': duration_ms,
        'success': success,
        'performance_log': True,
        'context': context
    }
    
    level = logging.INFO if success else logging.WARNING
    message = f"{operation} completed in {duration_ms:.2f}ms"
    
    logger.log(level, message, extra=extra)


def log_security_event(
    logger: logging.Logger,
    event_type: str,
    severity: str,
    message: str,
    **context
):
    """Log a security-related event"""
    extra = {
        'security_event': True,
        'event_type': event_type,
        'severity': severity,
        'component': 'security_monitor',
        'context': context
    }
    
    # Map severity to log level
    level_mapping = {
        'low': logging.INFO,
        'medium': logging.WARNING,
        'high': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    level = level_mapping.get(severity.lower(), logging.INFO)
    logger.log(level, message, extra=extra)


# Convenience function to set up basic logging for development
def setup_dev_logging():
    """Set up development logging with console output"""
    return setup_logging(
        log_level="DEBUG",
        enable_console=True,
        enable_security_logging=True,
        enable_performance_logging=True,
        log_format="structured"
    )


# Convenience function to set up production logging
def setup_prod_logging(log_dir: str = "/var/log/soar"):
    """Set up production logging with file output"""
    return setup_logging(
        log_level="INFO",
        log_file=f"{log_dir}/soar_system.log",
        enable_console=False,
        enable_security_logging=True,
        enable_performance_logging=True,
        log_format="structured",
        max_file_size=50 * 1024 * 1024,  # 50MB
        backup_count=10
    )
