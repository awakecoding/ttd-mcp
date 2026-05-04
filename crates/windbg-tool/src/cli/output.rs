use anyhow::{bail, Context};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct OutputOptions {
    pub(super) compact: bool,
    pub(super) field: Option<String>,
    pub(super) raw: bool,
}

pub(super) fn print_value(mut value: Value, output: &OutputOptions) -> anyhow::Result<()> {
    if let Some(path) = output.field.as_deref() {
        value = select_field(&value, path)?;
    }

    if output.raw {
        print_raw(value)
    } else if output.compact {
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    }
}

fn select_field(value: &Value, path: &str) -> anyhow::Result<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            bail!("field path contains an empty segment")
        }
        current = match current {
            Value::Object(object) => object
                .get(segment)
                .with_context(|| format!("field '{segment}' was not found"))?,
            Value::Array(items) => {
                let index = segment
                    .parse::<usize>()
                    .with_context(|| format!("array field segment '{segment}' is not an index"))?;
                items
                    .get(index)
                    .with_context(|| format!("array index {index} is out of range"))?
            }
            _ => bail!("field '{segment}' cannot be selected from a scalar value"),
        };
    }
    Ok(current.clone())
}

fn print_raw(value: Value) -> anyhow::Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(value) => {
            println!("{value}");
            Ok(())
        }
        Value::Number(value) => {
            println!("{value}");
            Ok(())
        }
        Value::String(value) => {
            println!("{value}");
            Ok(())
        }
        other => {
            println!("{}", serde_json::to_string(&other)?);
            Ok(())
        }
    }
}
