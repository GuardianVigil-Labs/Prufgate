"""PrufGate Hybrid Diff & PR Review Engine (`prufgate/review`)."""

from prufgate.review.ai_adapter import AIReviewResult, detect_ai_provider, review_diff_with_ai
from prufgate.review.reviewer import (
    PRComment,
    analyze_diff,
    format_review_github,
    format_review_markdown,
    format_review_reviewdog,
    format_review_sarif,
    get_git_diff,
    is_valid_code_suggestion,
    main,
    parse_diff_hunks,
    run_hybrid_review,
    run_self_check,
)

__all__ = [
    "AIReviewResult",
    "PRComment",
    "analyze_diff",
    "detect_ai_provider",
    "format_review_github",
    "format_review_markdown",
    "format_review_reviewdog",
    "format_review_sarif",
    "get_git_diff",
    "is_valid_code_suggestion",
    "main",
    "parse_diff_hunks",
    "review_diff_with_ai",
    "run_hybrid_review",
    "run_self_check",
]
