# ================================
# Project: CodeGuardian
# Description:
# A guardian-like repository meant for secure, stable,
# and well-crafted code with a spark of innovation.
# ================================

# ---------- main.py ----------
"""
Main entry point for CodeGuardian.
"""

from core.security import SecurityLayer
from core.stability import StabilityMonitor
from core.innovation import InnovationSpark


def run():
    print("🛡 Code Activated")
    print("🔒 Secure | 🧱 Stable | 💡 Innovative\n")

    security = SecurityLayer()
    stability = StabilityMonitor()
    innovation = InnovationSpark()

    # Security demo
    print("🔐 Hashed Token:", security.hash_value("guardian-key"))
    print("🔑 Password Valid:", security.validate_password("StrongPass1"))

    # Stability demo
    metrics = [100, 102, 98, 101]
    print("📊 Stability Score:", stability.consistency_score(metrics))

    # Innovation demo
    print("💡 Spark Output:", innovation.generate_signature("secure_system"))


if __name__ == "__main__":
    run()


# ---------- core/security.py ----------
"""
Security utilities for encryption, validation, and safe operations.
"""

import hashlib
import re

class SecurityLayer:
    """Provides secure hashing and validation mechanisms."""

    def hash_value(self, value: str) -> str:
        """Return SHA-256 hash of a value."""
        return hashlib.sha256(value.encode()).hexdigest()

    def validate_password(self, password: str) -> bool:
        """
        Validate password strength:
        - At least 8 characters
        - Contains uppercase, lowercase, and digit
        """
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        return True


# ---------- core/stability.py ----------
"""
Stability monitoring and system health checks.
"""

import statistics

class StabilityMonitor:
    """Ensures system consistency and durability."""

    def consistency_score(self, values):
        """Return stability score based on variance."""
        if not values:
            return 0
        variance = statistics.pvariance(values)
        return round(100 / (1 + variance), 2)

    def is_stable(self, values, threshold=50):
        """Check if system meets stability threshold."""
        return self.consistency_score(values) >= threshold


# ---------- core/innovation.py ----------
"""
Lightweight innovation module — adds a creative spark.
"""

class InnovationSpark:
    """Injects creative yet controlled enhancements."""

    def generate_signature(self, name: str) -> str:
        """Create a unique innovation signature."""
        return f"{name.upper()}_GX-{len(name)*7}"


# ---------- tests/test_security.py ----------
"""
Tests for SecurityLayer.
"""

from core.security import SecurityLayer

def test_hash_value():
    sec = SecurityLayer()
    assert len(sec.hash_value("test")) == 64

def test_validate_password():
    sec = SecurityLayer()
    assert sec.validate_password("StrongPass1")
    assert not sec.validate_password("weak")


# ---------- tests/test_stability.py ----------
"""
Tests for StabilityMonitor.
"""

from core.stability import StabilityMonitor

def test_consistency_score():
    monitor = StabilityMonitor()
    score = monitor.consistency_score([10, 10, 10])
    assert score > 90

