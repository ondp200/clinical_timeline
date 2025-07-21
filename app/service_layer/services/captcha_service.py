"""CAPTCHA service - pure business logic for CAPTCHA generation and validation."""
import random
from typing import Tuple


class CaptchaService:
    """Service for CAPTCHA operations - no session state dependencies."""
    
    def generate_challenge(self) -> Tuple[int, int]:
        """Generate new CAPTCHA challenge."""
        x = random.randint(1, 9)
        y = random.randint(1, 9)
        return x, y
    
    def get_challenge_text(self, x: int, y: int) -> str:
        """Get CAPTCHA challenge text."""
        return f"What is {x} + {y}?"
    
    def validate_answer(self, x: int, y: int, answer: str) -> bool:
        """Validate CAPTCHA answer."""
        try:
            return int(answer) == (x + y)
        except (ValueError, TypeError):
            return False
    
    def get_expected_answer(self, x: int, y: int) -> int:
        """Get expected answer for challenge."""
        return x + y