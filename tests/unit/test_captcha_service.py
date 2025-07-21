"""
CAPTCHA Service Unit Tests

Purpose: Test CAPTCHA generation and validation business logic
Scope: CaptchaService class
Dependencies: No external dependencies (pure business logic)

Test Categories:
1. Challenge generation
2. Answer validation
3. Text formatting
4. Edge cases and error handling
"""

import pytest
from service_layer.services import CaptchaService


class TestCaptchaService:
    """Test suite for CAPTCHA generation and validation."""
    
    def test_generate_challenge_returns_two_integers(self, captcha_service):
        """
        Test: Challenge generation produces two random integers
        
        Given: CaptchaService instance
        When: generate_challenge() is called
        Then: Returns tuple of two integers
        And: Both integers are between 1 and 9 inclusive
        """
        # Act
        x, y = captcha_service.generate_challenge()
        
        # Assert
        assert isinstance(x, int)
        assert isinstance(y, int)
        assert 1 <= x <= 9
        assert 1 <= y <= 9
    
    def test_generate_challenge_produces_different_values(self, captcha_service):
        """
        Test: Multiple challenge generations produce varied results
        
        Given: CaptchaService instance
        When: generate_challenge() is called multiple times
        Then: At least some challenges are different
        (Note: Small chance of false positive due to randomness)
        """
        # Act - Generate multiple challenges
        challenges = [captcha_service.generate_challenge() for _ in range(20)]
        
        # Assert - Should have some variety (not all identical)
        unique_challenges = set(challenges)
        assert len(unique_challenges) > 1
    
    def test_get_challenge_text_formats_correctly(self, captcha_service):
        """
        Test: Challenge text is formatted correctly
        
        Given: Two integers x and y
        When: get_challenge_text() is called
        Then: Returns formatted question string
        And: Contains both numbers in expected format
        """
        # Arrange
        x, y = 3, 7
        
        # Act
        challenge_text = captcha_service.get_challenge_text(x, y)
        
        # Assert
        assert challenge_text == "What is 3 + 7?"
        assert str(x) in challenge_text
        assert str(y) in challenge_text
        assert "+" in challenge_text
        assert "?" in challenge_text
    
    def test_validate_answer_succeeds_with_correct_answer(self, captcha_service):
        """
        Test: Answer validation succeeds with correct sum
        
        Given: Challenge numbers and correct sum as string
        When: validate_answer() is called
        Then: Returns True
        """
        # Arrange
        x, y = 4, 6
        correct_answer = "10"
        
        # Act
        result = captcha_service.validate_answer(x, y, correct_answer)
        
        # Assert
        assert result == True
    
    def test_validate_answer_fails_with_incorrect_answer(self, captcha_service):
        """
        Test: Answer validation fails with incorrect sum
        
        Given: Challenge numbers and incorrect sum as string
        When: validate_answer() is called
        Then: Returns False
        """
        # Arrange
        x, y = 4, 6
        incorrect_answer = "9"
        
        # Act
        result = captcha_service.validate_answer(x, y, incorrect_answer)
        
        # Assert
        assert result == False
    
    def test_validate_answer_handles_non_numeric_input(self, captcha_service):
        """
        Test: Answer validation handles non-numeric input gracefully
        
        Given: Challenge numbers and non-numeric string
        When: validate_answer() is called
        Then: Returns False (doesn't raise exception)
        """
        # Arrange
        x, y = 4, 6
        non_numeric_answer = "abc"
        
        # Act
        result = captcha_service.validate_answer(x, y, non_numeric_answer)
        
        # Assert
        assert result == False
    
    def test_validate_answer_handles_empty_input(self, captcha_service):
        """
        Test: Answer validation handles empty input gracefully
        
        Given: Challenge numbers and empty string
        When: validate_answer() is called
        Then: Returns False (doesn't raise exception)
        """
        # Arrange
        x, y = 4, 6
        empty_answer = ""
        
        # Act
        result = captcha_service.validate_answer(x, y, empty_answer)
        
        # Assert
        assert result == False
    
    def test_validate_answer_handles_none_input(self, captcha_service):
        """
        Test: Answer validation handles None input gracefully
        
        Given: Challenge numbers and None as answer
        When: validate_answer() is called
        Then: Returns False (doesn't raise exception)
        """
        # Arrange
        x, y = 4, 6
        none_answer = None
        
        # Act
        result = captcha_service.validate_answer(x, y, none_answer)
        
        # Assert
        assert result == False
    
    def test_validate_answer_accepts_integer_input(self, captcha_service):
        """
        Test: Answer validation accepts integer input
        
        Given: Challenge numbers and correct sum as integer
        When: validate_answer() is called with integer
        Then: Returns True
        """
        # Arrange
        x, y = 5, 3
        integer_answer = 8
        
        # Act
        result = captcha_service.validate_answer(x, y, str(integer_answer))
        
        # Assert
        assert result == True
    
    def test_get_expected_answer_returns_correct_sum(self, captcha_service):
        """
        Test: Expected answer calculation returns correct sum
        
        Given: Two challenge numbers
        When: get_expected_answer() is called
        Then: Returns correct mathematical sum
        """
        # Arrange
        x, y = 7, 8
        
        # Act
        expected = captcha_service.get_expected_answer(x, y)
        
        # Assert
        assert expected == 15
        assert expected == x + y
    
    def test_validate_answer_with_leading_trailing_spaces(self, captcha_service):
        """
        Test: Answer validation handles whitespace in input
        
        Given: Challenge numbers and answer with extra whitespace
        When: validate_answer() is called
        Then: Returns True for correct answer despite whitespace
        """
        # Arrange
        x, y = 2, 9
        answer_with_spaces = "  11  "
        
        # Act
        result = captcha_service.validate_answer(x, y, answer_with_spaces)
        
        # Assert
        assert result == True  # int() strips whitespace automatically
    
    def test_edge_case_maximum_sum(self, captcha_service):
        """
        Test: CAPTCHA works correctly with maximum possible sum
        
        Given: Maximum challenge numbers (9, 9)
        When: Validating maximum sum (18)
        Then: Validation succeeds
        """
        # Arrange
        x, y = 9, 9
        max_answer = "18"
        
        # Act
        result = captcha_service.validate_answer(x, y, max_answer)
        
        # Assert
        assert result == True
    
    def test_edge_case_minimum_sum(self, captcha_service):
        """
        Test: CAPTCHA works correctly with minimum possible sum
        
        Given: Minimum challenge numbers (1, 1)
        When: Validating minimum sum (2)
        Then: Validation succeeds
        """
        # Arrange
        x, y = 1, 1
        min_answer = "2"
        
        # Act
        result = captcha_service.validate_answer(x, y, min_answer)
        
        # Assert
        assert result == True