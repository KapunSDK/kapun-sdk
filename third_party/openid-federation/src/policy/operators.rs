/* Copyright 2025 Ubique Innovation AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use crate::models::{
    self,
    errors::{FederationError, PayloadError, PolicyError},
    transformer::{self, Value},
};

fn subset(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(a) = a.argument() else {
        return false;
    };
    let Value::Array(b) = b.argument() else {
        return false;
    };
    for item in b {
        if !a.contains(&item) {
            return false;
        }
    }
    true
}
fn superset(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    subset(b, a)
}
fn is_same(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    a == b && a.argument() == b.argument()
}
fn not_null(a: &PolicyOperator, _b: &PolicyOperator) -> bool {
    matches!(a.argument(), Value::Null)
}
fn other_not_null(_a: &PolicyOperator, b: &PolicyOperator) -> bool {
    matches!(b.argument(), Value::Null)
}
fn contains(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(a) = a.argument() else {
        return false;
    };
    a.contains(&b.argument())
}

fn contained_in(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Array(b) = b.argument() else {
        return false;
    };
    b.contains(&a.argument())
}
fn check_essential(a: &PolicyOperator, b: &PolicyOperator) -> bool {
    let Value::Boolean(b) = b.argument() else {
        return false;
    };
    if !b {
        return true;
    }
    matches!(a.argument(), Value::Null)
}

crate::operator_definitions!(
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub enum PolicyOperator {
        Value(Value::String(..) | Value::Integer(..) | Value::Float(..) | Value::Boolean(..) | Value::Array(..) ) = "value"
        // Allowed combinations
            => [Value|is_same|, Add |subset|,Default|not_null|, OneOf|contained_in|, SubsetOf|subset|, SupersetOf|superset|, Essential|check_essential|]
        ,
        Add(Value::Array(..)) = "add"
            => [Add, Value |subset|, Default, SubsetOf|subset|, SupersetOf, Essential],
        Default(_any) = "default"
            => [Default|is_same|, Value|other_not_null|, Add, OneOf, SubsetOf, SupersetOf, Essential],
        OneOf(Value::String(..)) = "one_of"
            => [OneOf, Value|contains|, Default, Essential],
        SubsetOf(Value::Array(..)) = "subset_of"
            => [SubsetOf, Value|subset|, Add|subset|, Default, SupersetOf|superset|, Essential],
        SupersetOf(Value::Array(..)) = "superset_of"
            => [SupersetOf, Value|superset|, Add, Default, SubsetOf|superset|, Essential],
        Essential(Value::Boolean(..)) = "essential" => [Essential],
    }
);

#[macro_export]
/// Define operators specifying merge conditions and allowed combinations with other operators
/// The order implies order of application when merging policies
macro_rules! operator_definitions {
    ($(#[$($meta:tt)*])* $v:vis enum $name:ident {
            $(
                $(#[$($meta_var:tt)*])*
                $operator_name:ident($tokens:pat) = $value:expr $(=> [$($allowed_operator:ident$(|$($fname:ident),*|)?),*])? $(;mergable => $mergable_cond:ident)?
            ),*,
        }) => {
            $(#[$($meta)*])*
            $v enum $name {
                $(
                    $(#[$($meta_var)*])*
                    #[serde(alias = $value)]
                    $operator_name($crate::models::transformer::Value)
                ),*,
                #[serde(other)]
                Unknown
            }
            impl From<&transformer::Value> for Vec<PolicyOperator> {
                fn from(v: &transformer::Value) -> Vec<PolicyOperator> {
                    let Some(obj) = v.as_object() else {
                        return vec![];
                    };
                    let mut operators = Vec::new();
                    for (key, value) in obj {
                        match key.as_str() {
                            $($value => operators.push(PolicyOperator::$operator_name(value.clone()))),*,
                            _ => operators.push(PolicyOperator::Unknown),
                        }
                    }
                    operators.sort_by(|a, b| a.number().cmp(&b.number()));
                    operators
                }
            }
            impl PolicyOperator {
                pub const fn number(&self) -> u32 {
                    let mut number = 0;
                    $(
                        if matches!(self, PolicyOperator::$operator_name(..)) {
                            return number;
                        }
                        number += 1;
                    )?
                    return number;
                }
                pub fn argument(&self) -> $crate::models::transformer::Value {
                    match self {
                        $(PolicyOperator::$operator_name(value) => value.clone()),*,
                        Self::Unknown => models::transformer::Value::Null,
                    }
                }
                pub fn valid_data_type(&self, data: &Value) -> bool {
                    match self {
                        $(PolicyOperator::$operator_name(..) => matches!(data, $tokens)),*,
                        Self::Unknown => false
                    }
                }
                pub fn can_be_combined_with(&self, other: &[PolicyOperator]) -> bool {
                    match self {
                        $(
                            PolicyOperator::$operator_name(_) => {
                                false $( || other.iter().all(|o| match o {
                                        $(
                                            PolicyOperator::$allowed_operator(..) $(if $($fname(self, o))&&*)? => true,
                                        )*
                                         _ => false
                                    } )
                                )? }
                        )*
                        PolicyOperator::Unknown => false
                    }
                }
                pub fn name(&self) -> &str {
                    match self {
                        $(PolicyOperator::$operator_name(..) => $value),*,
                        Self::Unknown => "Unknown",
                    }
                }
            }
        };
}

impl PolicyOperator {
    #[instrument(err)]
    pub fn apply(&self, val: &mut Value) -> Result<(), FederationError> {
        match self {
            PolicyOperator::Value(value) => {
                *val = value.clone();
            }
            PolicyOperator::Add(value) => {
                if matches!(val, Value::Null) {
                    *val = value.clone();
                    return Ok(());
                }
                if let (Value::Array(array), Value::Array(new_values)) = (val, value) {
                    for new_value in new_values {
                        if array.contains(new_value) {
                            continue;
                        }
                        array.push(new_value.clone());
                    }
                } else {
                    return Err(PolicyError::InvalidPolicyOperator(
                        "add operator requires array value".to_string(),
                    )
                    .into());
                }
            }
            PolicyOperator::Default(value) => {
                if matches!(val, Value::Null) {
                    *val = value.clone();
                }
            }
            PolicyOperator::OneOf(value) => {
                if matches!(val, Value::Null) {
                    return Ok(());
                }
                let Value::Array(vals) = value else {
                    return Err(PolicyError::InvalidPolicyOperator(
                        "one_of operator requires array value".to_string(),
                    )
                    .into());
                };
                if !vals.contains(val) {
                    return Err(PolicyError::InvalidPolicyOperator(
                        "value not in one_of list".to_string(),
                    )
                    .into());
                }
            }
            PolicyOperator::SubsetOf(value) => {
                if matches!(val, Value::Null) {
                    return Ok(());
                }
                let result = intersect_values(val, value)?;
                *val = Value::Array(result.into_iter().cloned().collect());
            }
            PolicyOperator::SupersetOf(value) => {
                if !a_is_superset_of_b(val, value)? {
                    return Err(PolicyError::InvalidPolicyOperator(
                        "value not in superset".to_string(),
                    )
                    .into());
                }
            }
            PolicyOperator::Essential(value) => {
                let &Value::Boolean(essential) = value else {
                    return Err(PolicyError::InvalidPolicyOperator(
                        "value not a boolean".to_string(),
                    )
                    .into());
                };
                if essential && matches!(val, Value::Null) {
                    return Err(
                        PolicyError::InvalidPolicyOperator("value is null".to_string()).into(),
                    );
                }
            }
            PolicyOperator::Unknown => {
                // TODO: check crit claims in policy object
                return Err(
                    PolicyError::InvalidPolicyOperator("unknown operator".to_string()).into(),
                );
            }
        }
        Ok(())
    }
    #[instrument(err)]
    pub fn merge(&mut self, other: &PolicyOperator) -> Result<(), FederationError> {
        match self {
            PolicyOperator::Value(_) => {}
            PolicyOperator::Add(value) => {
                if let Value::Array(other) = other.argument() {
                    value.as_array_mut().unwrap().extend(other);
                }
            }
            PolicyOperator::Default(_) => {}
            PolicyOperator::OneOf(value) => {
                let intersection: Vec<Value> = intersect_values(value, &other.argument())?
                    .into_iter()
                    .cloned()
                    .collect();
                if intersection.is_empty() {
                    return Err(PolicyError::InvalidPolicyOperator(format!(
                        "No intersection found between {:?} and {:?}",
                        value,
                        other.argument()
                    ))
                    .into());
                }
                *value = Value::Array(intersection);
            }
            PolicyOperator::SubsetOf(value) => {
                let intersection: Vec<Value> = intersect_values(value, &other.argument())?
                    .into_iter()
                    .cloned()
                    .collect();
                *value = Value::Array(intersection);
            }
            PolicyOperator::SupersetOf(value) => {
                let intersection: Vec<Value> = union_values(value, &other.argument())?
                    .into_iter()
                    .cloned()
                    .collect();
                *value = Value::Array(intersection);
            }
            PolicyOperator::Essential(value) => {
                *value = Value::Boolean(
                    value.as_bool().unwrap_or(false) || other.argument().as_bool().unwrap_or(false),
                );
            }
            p => {
                warn!("{p:?} is unknown")
            }
        }
        Ok(())
    }
}

#[instrument(err)]
fn a_is_superset_of_b<'a>(a: &'a Value, b: &'a Value) -> Result<bool, FederationError> {
    let Value::Array(self_array) = a else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            a
        ))
        .into());
    };
    let Value::Array(other_array) = b else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            b
        ))
        .into());
    };

    // ahm naja, could be better...
    let set: HashSet<&Value> = HashSet::from_iter(self_array.iter());
    let set2: HashSet<&Value> = HashSet::from_iter(other_array.iter());

    Ok(set.is_superset(&set2))
}

#[instrument(err)]
fn intersect_values<'a>(a: &'a Value, b: &'a Value) -> Result<Vec<&'a Value>, FederationError> {
    let Value::Array(self_array) = a else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            a
        ))
        .into());
    };
    let Value::Array(other_array) = b else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            b
        ))
        .into());
    };

    // ahm naja, could be better...
    let set: HashSet<&Value> = HashSet::from_iter(self_array.iter());
    let set2: HashSet<&Value> = HashSet::from_iter(other_array.iter());
    let result = set.intersection(&set2).cloned().collect::<Vec<_>>();

    Ok(result)
}

#[instrument(err)]
fn union_values<'a>(a: &'a Value, b: &'a Value) -> Result<Vec<&'a Value>, FederationError> {
    let Value::Array(self_array) = a else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            a
        ))
        .into());
    };
    let Value::Array(other_array) = b else {
        return Err(PolicyError::InvalidPolicyOperator(format!(
            "Expected array for intersection operator, found {:?}",
            b
        ))
        .into());
    };

    // ahm naja, could be better...
    let set: HashSet<&Value> = HashSet::from_iter(self_array.iter());
    let set2: HashSet<&Value> = HashSet::from_iter(other_array.iter());
    let result = set.union(&set2).cloned().collect::<Vec<_>>();

    Ok(result)
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Policy {
    #[serde(flatten)]
    pub policy_members: HashMap<String, Value>,
}

impl Policy {
    #[instrument(err)]
    pub fn merge_with(&mut self, other: &Policy) -> Result<(), FederationError> {
        for (key, value) in other.policy_members.iter() {
            let member_policy = self
                .policy_members
                .entry(key.to_string())
                .or_insert(Value::Object(HashMap::new()));
            let other_operators: Vec<PolicyOperator> = value.into();
            let mut self_operators: Vec<PolicyOperator> = (&member_policy.clone()).into();
            for other in &other_operators {
                if !other.can_be_combined_with(&self_operators) {
                    return Err(PolicyError::PolicyMergeError(format!(
                        "Cannot merge policies with incompatible operators: {:?} and {:?}",
                        self_operators, other
                    ))
                    .into());
                }
                if let Some(same_operator) = self_operators
                    .iter_mut()
                    .find(|self_ops| other.name() == self_ops.name())
                {
                    same_operator.merge(other)?;
                } else {
                    self_operators.push(other.clone());
                }
            }
            for operator in self_operators {
                member_policy
                    .as_object_mut()
                    .unwrap()
                    .insert(operator.name().to_string(), operator.argument());
            }
        }
        Ok(())
    }
    pub fn apply(&self, object: &mut Value) -> Result<(), FederationError> {
        let Some(obj) = object.as_object_mut() else {
            return Err(PolicyError::MetadataMustBeObject(format!("{:?}", object)).into());
        };
        for (key, value) in &self.policy_members {
            let operators: Vec<PolicyOperator> = value.into();
            let object_value = obj.entry(key.to_string()).or_insert(Value::Null);
            for operator in operators {
                operator.apply(object_value)?;
            }
            if matches!(object_value, Value::Null) {
                obj.remove(key);
            }
        }
        Ok(())
    }
}

impl TryFrom<serde_json::Value> for Policy {
    type Error = FederationError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| {
            FederationError::Payload(PayloadError::MissingRequiredProperty(format!("{e}")))
        })
    }
}

#[cfg(test)]
mod tests {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::{FmtSubscriber, fmt::format::FmtSpan};

    use crate::{
        models::transformer::Value,
        policy::operators::{Policy, PolicyOperator},
    };

    #[test]
    fn test_basic_policy() {
        let policy = include_str!("../../test_resources/figure_11_metadata_policy.json");
        let policy: Policy = serde_json::from_str(policy).unwrap();
        for (attr, policy) in policy.policy_members {
            let operators: Vec<PolicyOperator> = (&policy).into();
            println!("{}{:?}", attr, operators)
        }
    }
    #[test]
    fn test_merge() {
        let subscriber = FmtSubscriber::builder()
            .with_line_number(true)
            .with_max_level(LevelFilter::DEBUG)
            .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
            .pretty()
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        let policy1 = include_str!("../../test_resources/figure54_policy1.json");
        let policy2 = include_str!("../../test_resources/figure58_policy2.json");
        let policy3 = include_str!("../../test_resources/figure62_policy3.json");
        let policy4 = include_str!("../../test_resources/figure66_policy4.json");
        let mut metadata: Value = serde_json::from_str(policy1).unwrap();
        let policy2: Policy = serde_json::from_str(policy2).unwrap();
        let policy3: Policy = serde_json::from_str(policy3).unwrap();
        let mut policy4: Policy = serde_json::from_str(policy4).unwrap();

        policy4.merge_with(&policy3).unwrap();
        policy4.merge_with(&policy2).unwrap();
        policy4.apply(&mut metadata).unwrap();
        let merged_data = serde_json::from_str::<Value>(include_str!(
            "../../test_resources/figure67_resolved_metadata.json"
        ))
        .unwrap();
        println!("{:?}", compare_values(&metadata, &merged_data));
    }

    fn equal_ignore_order(left: &Value, right: &Value) -> bool {
        match (left, right) {
            (Value::Array(left), Value::Array(right)) => {
                left.iter().all(|item| right.contains(item))
            }

            (Value::Object(left), Value::Object(right)) => left.iter().all(|(key, val)| {
                if let Some(right_val) = right.get(key) {
                    equal_ignore_order(val, right_val)
                } else {
                    false
                }
            }),

            _ => left == right,
        }
    }

    fn compare_values<'a>(left: &'a Value, right: &'a Value) -> Vec<(&'a Value, &'a Value)> {
        let left_object = left.as_object().unwrap();
        let right_object = right.as_object().unwrap();
        let mut differences = vec![];
        for (key, val) in left_object {
            if let Some(right_val) = right_object.get(key) {
                if !equal_ignore_order(val, right_val) {
                    differences.push((val, right_val));
                }
            }
        }
        for right_key in right_object.keys() {
            if !left_object.contains_key(right_key) {
                differences.push((&Value::Null, right_object.get(right_key).unwrap()));
            }
        }
        differences
    }
}
