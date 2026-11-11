"""Regression tests for the weighted final SOC challenge."""
import itertools
import unittest
from unittest.mock import patch

from routes.final_soc_challenge import QUESTIONS, PASS_PERCENTAGE, public_questions, score_answers


class FinalSOCScoringTests(unittest.TestCase):
    def test_question_ids_and_marks_distribution(self):
        self.assertEqual([question["id"] for question in QUESTIONS], [f"q{number}" for number in range(1, 8)])
        self.assertEqual([question["weight"] for question in QUESTIONS], [16] * 5 + [10, 10])
        self.assertEqual(sum(question["weight"] for question in QUESTIONS), 100)
        self.assertEqual(PASS_PERCENTAGE, 70)
        for question in QUESTIONS:
            choices = dict(question["options"])
            self.assertEqual(len(choices), len(question["options"]))
            self.assertIn(question["answer"], choices)

    def test_all_correct_and_empty_answers(self):
        self.assertEqual(score_answers({question["id"]: question["answer"] for question in QUESTIONS}),
                         {"score": 100, "percentage": 100, "passed": True})
        self.assertEqual(score_answers({}), {"score": 0, "percentage": 0, "passed": False})

    def test_each_question_awards_only_its_weight(self):
        for question in QUESTIONS:
            with self.subTest(question=question["id"]):
                self.assertEqual(score_answers({question["id"]: question["answer"]})["score"], question["weight"])

    def test_all_128_correct_incorrect_combinations(self):
        for flags in itertools.product((False, True), repeat=7):
            answers = {question["id"]: question["answer"] if correct else next(
                value for value, _ in question["options"] if value != question["answer"])
                for question, correct in zip(QUESTIONS, flags)}
            expected = sum(question["weight"] for question, correct in zip(QUESTIONS, flags) if correct)
            with self.subTest(correct=flags):
                self.assertEqual(score_answers(answers),
                                 {"score": expected, "percentage": expected, "passed": expected >= 70})

    def test_missing_invalid_and_extra_answers_cannot_award_marks(self):
        answers = {question["id"]: "invalid" for question in QUESTIONS}
        answers.update(score=100, percentage=100, passed=True, q8="a")
        self.assertEqual(score_answers(answers)["score"], 0)

    def test_64_fails_and_74_passes(self):
        answers = {question["id"]: question["answer"] for question in QUESTIONS[:4]}
        self.assertEqual(score_answers(answers), {"score": 64, "percentage": 64, "passed": False})
        answers["q6"] = QUESTIONS[5]["answer"]
        self.assertEqual(score_answers(answers), {"score": 74, "percentage": 74, "passed": True})

    def test_exact_70_percent_threshold(self):
        for weight, passed in ((69, False), (70, True)):
            questions = ({"id": "first", "answer": "a", "weight": weight},
                         {"id": "second", "answer": "b", "weight": 100 - weight})
            with patch("routes.final_soc_challenge.QUESTIONS", questions):
                self.assertEqual(score_answers({"first": "a"})["passed"], passed)

    def test_invalid_weight_total_is_rejected(self):
        questions = tuple(dict(question) for question in QUESTIONS)
        questions[0]["weight"] += 1
        with patch("routes.final_soc_challenge.QUESTIONS", questions):
            with self.assertRaisesRegex(ValueError, "weights must total 100"):
                score_answers({})

    def test_public_questions_exclude_private_rubric(self):
        public = public_questions()
        self.assertEqual(len(public), 7)
        for question in public:
            self.assertEqual(set(question), {"id", "title", "prompt", "options", "weight"})
            for private in ("answer", "expected", "evidence", "files"):
                self.assertNotIn(private, question)
        public[0]["title"] = "Changed by caller"
        self.assertNotEqual(public_questions()[0]["title"], "Changed by caller")


if __name__ == "__main__":
    unittest.main()
