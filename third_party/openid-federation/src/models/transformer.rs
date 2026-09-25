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

use std::{collections::HashMap, ops::Deref};

use itertools::Itertools;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub trait Transformer {
    fn set_field(&mut self, name: &str, value: Value);
    fn transform(self, transformer: &mut dyn Transformer) -> Result<(), String>;
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone, Debug, Copy)]
pub struct Float(f64);
impl Eq for Float {}
impl std::hash::Hash for Float {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl From<&Float> for f64 {
    fn from(value: &Float) -> Self {
        value.0
    }
}
impl From<Float> for f64 {
    fn from(value: Float) -> Self {
        value.0
    }
}

impl From<f64> for Float {
    fn from(value: f64) -> Self {
        Float(value)
    }
}
impl From<&f64> for Float {
    fn from(value: &f64) -> Self {
        Float(*value)
    }
}
impl AsRef<f64> for Float {
    fn as_ref(&self) -> &f64 {
        &self.0
    }
}
impl Deref for Float {
    type Target = f64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq)]
#[serde(untagged)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    Float(Float),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
    #[serde(alias = "null")]
    Null,
}
impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Value::String(s) => s.hash(state),
            Value::Integer(i) => i.hash(state),
            Value::Boolean(b) => b.hash(state),
            Value::Float(f) => f.hash(state),
            Value::Array(a) => a.hash(state),
            Value::Object(o) => o.iter().sorted_by(|a, b| a.0.cmp(b.0)).for_each(|tup| {
                tup.hash(state);
            }),
            Value::Null => {}
        }
    }
}
impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Integer(i) => Some(*i as u64),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(f.into()),
            _ => None,
        }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn into_typed_array<T: Serialize + DeserializeOwned>(&self) -> Option<Vec<T>> {
        match self {
            Value::Array(a) => {
                let mut result = Vec::new();
                for item in a {
                    if let Ok(value) = serde_json::from_value(item.clone().into()) {
                        result.push(value);
                    } else {
                        return None;
                    }
                }
                Some(result)
            }
            _ => None,
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut HashMap<String, Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&HashMap<String, Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
    pub fn write_to_transformer(&self, transformer: &mut dyn Transformer) {
        if let Some(object) = self.as_object() {
            for (key, value) in object {
                transformer.set_field(key, value.clone());
            }
        }
    }
}
impl From<Value> for serde_json::Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => serde_json::Value::Null,
            Value::Boolean(b) => serde_json::Value::Bool(b),
            Value::Integer(i) => serde_json::Value::Number(serde_json::Number::from(i)),
            Value::Float(f) => {
                serde_json::Value::Number(serde_json::Number::from_f64(f.into()).unwrap())
            }
            Value::String(s) => serde_json::Value::String(s),
            Value::Array(a) => serde_json::Value::Array(a.into_iter().map(|v| v.into()).collect()),
            Value::Object(o) => {
                serde_json::Value::Object(o.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}
impl From<Value> for Option<serde_json::Value> {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => None,
            Value::Boolean(b) => Some(serde_json::Value::Bool(b)),
            Value::Integer(i) => Some(serde_json::Value::Number(serde_json::Number::from(i))),
            Value::Float(f) => Some(serde_json::Value::Number(
                serde_json::Number::from_f64(f.into()).unwrap(),
            )),
            Value::String(s) => Some(serde_json::Value::String(s)),
            Value::Array(a) => Some(serde_json::Value::Array(
                a.into_iter().map(|v| v.into()).collect(),
            )),
            Value::Object(o) => Some(serde_json::Value::Object(
                o.into_iter().map(|(k, v)| (k, v.into())).collect(),
            )),
        }
    }
}

impl From<serde_json::Value> for Value {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Boolean(b),
            serde_json::Value::Number(number) => {
                if let Some(i64) = number.as_i64() {
                    Value::Integer(i64)
                } else if let Some(f64) = number.as_f64() {
                    Value::Float(f64.into())
                } else {
                    Value::Null
                }
            }
            serde_json::Value::String(s) => Value::String(s),
            serde_json::Value::Array(values) => {
                Value::Array(values.into_iter().map(|a| a.into()).collect::<Vec<_>>())
            }
            serde_json::Value::Object(map) => {
                Value::Object(map.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

impl Transformer for Value {
    fn set_field(&mut self, name: &str, value: Value) {
        if let Value::Object(map) = self {
            map.insert(name.to_string(), value);
        }
    }

    fn transform(self, transformer: &mut dyn Transformer) -> Result<(), String> {
        if let Value::Object(map) = self {
            for (key, value) in map {
                transformer.set_field(&key, value);
            }
            return Ok(());
        }
        Err("Only available for objects".to_string())
    }
}
