/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */
//! # Possum
//! Possum is a business logic evalutation engine. It uses similiar functions as
//! JsonLogic but uses a more human centric programming like language.

use std::sync::Arc;
use uniffi::Object;

/// Why a Possum expression could not be parsed or evaluated.
#[derive(Debug, uniffi::Error)]
pub enum PossumError {
    /// The expression source is not valid Possum.
    Parse { reason: String },
    /// The data passed to the evaluation is not valid JSON.
    InvalidData { reason: String },
    /// The expression could not be evaluated against the data.
    Evaluation { reason: String },
}

impl std::fmt::Display for PossumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PossumError::Parse { reason } => write!(f, "Parse error: {reason}"),
            PossumError::InvalidData { reason } => write!(f, "Invalid data: {reason}"),
            PossumError::Evaluation { reason } => write!(f, "Evaluation error: {reason}"),
        }
    }
}

impl std::error::Error for PossumError {}

#[derive(Object)]
pub struct PossumExpression {
    expression: jlc::Expression,
}

#[uniffi::export]
impl PossumExpression {
    /// Parses a Possum expression, reporting invalid source as [PossumError::Parse].
    #[uniffi::constructor]
    pub fn parse(source: &str) -> Result<Arc<Self>, PossumError> {
        let expression = jlc::arithmetic::expression(source).map_err(|e| PossumError::Parse {
            reason: e.to_string(),
        })?;
        Ok(Arc::new(Self { expression }))
    }

    /// Evaluates the expression against the JSON `data` and returns the result as JSON.
    ///
    /// A missing value is the JSON `null`, not an error.
    pub fn evaluate_json(&self, data: &str) -> Result<String, PossumError> {
        Ok(self.evaluate_value(data)?.to_string())
    }

    /// Evaluates the expression and requires a boolean result.
    pub fn evaluate_bool(&self, data: &str) -> Result<bool, PossumError> {
        match self.evaluate_value(data)? {
            serde_json::Value::Bool(b) => Ok(b),
            other => Err(PossumError::Evaluation {
                reason: format!("expected a boolean, got {other}"),
            }),
        }
    }

    #[uniffi::constructor]
    pub fn from_str(str: &str) -> Arc<Self> {
        let Ok(expression) = jlc::arithmetic::expression(str) else {
            return Arc::new(Self {
                expression: jlc::Expression::Atomic(jlc::Value::Null),
            });
        };
        Arc::new(Self { expression })
    }
    pub fn evaluate(self: &Arc<Self>, data: &str) -> Arc<Self> {
        let Ok(data) = serde_json::from_str(data) else {
            return Arc::new(PossumExpression {
                expression: jlc::Expression::Atomic(jlc::Value::Null),
            });
        };
        Arc::new(Self {
            expression: self
                .expression
                .eval(&data)
                .unwrap_or(jlc::Expression::Atomic(jlc::Value::Null)),
        })
    }
    pub fn is_truthy(self: &Arc<Self>) -> bool {
        self.expression.as_bool().unwrap_or(false)
    }
    pub fn is_null(self: &Arc<Self>) -> bool {
        matches!(self.expression, jlc::Expression::Atomic(jlc::Value::Null))
    }
    pub fn as_json(self: &Arc<Self>) -> Option<String> {
        if let jlc::Expression::Atomic(v) = &self.expression {
            Some(v.to_serde_json().to_string())
        } else {
            None
        }
    }
}

impl PossumExpression {
    fn evaluate_value(&self, data: &str) -> Result<serde_json::Value, PossumError> {
        let data: serde_json::Value =
            serde_json::from_str(data).map_err(|e| PossumError::InvalidData {
                reason: e.to_string(),
            })?;
        // Evaluated as JsonLogic: Possum's own evaluator can't compare dates or booleans.
        jsonlogic::apply(&self.expression.to_json_logic(), &data).map_err(|e| PossumError::Evaluation {
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = r#"{
        "external": {"validationClock": "2026-10-27T10:15:00Z"},
        "claims": {
            "dateOfExpiration": "2031-10-27",
            "expired": "2026-07-06",
            "age_over_18": true,
            "licenceCategories": [{"categoryCode": "B"}, {"categoryCode": "C", "categoryDateOfExpiration": "2025-01-23"}]
        },
        "item": {"empty": "", "future": "2028-01-23", "past": "2025-01-23"},
        "rules": {"category_valid": {"passed": 1, "failed": 1, "firstFailed": {"categoryCode": "C"}}}
    }"#;

    fn json(source: &str) -> String {
        PossumExpression::parse(source).unwrap().evaluate_json(DATA).unwrap()
    }

    fn bool(source: &str) -> Result<bool, PossumError> {
        PossumExpression::parse(source).unwrap().evaluate_bool(DATA)
    }

    #[test]
    fn invalid_source_is_a_parse_error() {
        assert!(matches!(PossumExpression::parse("claims.x is after"), Err(PossumError::Parse { .. })));
    }

    #[test]
    fn invalid_data_is_reported() {
        let expression = PossumExpression::parse("true").unwrap();
        assert!(matches!(expression.evaluate_json("{"), Err(PossumError::InvalidData { .. })));
    }

    #[test]
    fn dates_compare_against_the_validation_clock() {
        assert!(bool("(claims.dateOfExpiration as DateTime) is after now()").unwrap());
        assert!(!bool("(claims.expired as DateTime) is after now()").unwrap());
        assert_eq!(json("(claims.missing as DateTime) is after now()"), "null");
    }

    #[test]
    fn missing_and_empty_values_are_falsy() {
        let unlimited = |field: &str| bool(&format!("(!item.{field}) or ((item.{field} as DateTime) is after now())")).unwrap();
        assert!(unlimited("missing"));
        assert!(unlimited("empty"));
        assert!(unlimited("future"));
        assert!(!unlimited("past"));
        assert!(bool("item.missing == null").unwrap());
    }

    #[test]
    fn booleans_and_numbers_compare() {
        assert!(bool("claims.age_over_18 == true").unwrap());
        assert!(!bool("claims.missing == true").unwrap());
        assert!(bool("rules.category_valid.failed > 0").unwrap());
        assert!(!bool("rules.category_valid.passed == 0").unwrap());
        assert!(!bool("!rules.category_valid.passed").unwrap());
    }

    #[test]
    fn non_boolean_results_are_returned_as_json() {
        assert_eq!(json("rules.category_valid.failed"), "1");
        assert_eq!(json("rules.category_valid.firstFailed.categoryCode"), "\"C\"");
        assert_eq!(json("rules.category_valid.firstFailed"), r#"{"categoryCode":"C"}"#);
        assert_eq!(json("claims.licenceCategories.1.categoryCode"), "\"C\"");
        assert_eq!(json("claims.missing"), "null");
        assert!(matches!(bool("claims.dateOfExpiration"), Err(PossumError::Evaluation { .. })));
    }
}
