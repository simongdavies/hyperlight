/*
Copyright 2024 The Hyperlight Authors.

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

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::{json, to_string_pretty, Value};
use tracing::Subscriber;
use tracing_core::event::Event;
use tracing_core::metadata::Metadata;
use tracing_core::span::{Attributes, Current, Id, Record};
use tracing_core::{Level, LevelFilter};
use tracing_serde::AsSerde;

#[derive(Debug, Clone)]
pub struct TracingSubscriber {}

thread_local!(
    static SPAN_METADATA: RefCell<HashMap<u64, &'static Metadata<'static>>> =
        RefCell::new(HashMap::new());
    static SPANS: RefCell<HashMap<u64, Value>> = RefCell::new(HashMap::new());
    static EVENTS: RefCell<Vec<Value>> = const { RefCell::new(Vec::new()) };
    static LEVEL_FILTER: RefCell<LevelFilter> = const { RefCell::new(LevelFilter::OFF) };
    static NEXT_ID: RefCell<u64> = const { RefCell::new(1) };
    static SPAN_STACK: RefCell<Vec<Id>> = const { RefCell::new(Vec::new()) };
);

impl TracingSubscriber {
    /// Creates a new TracingSubscriber with the specified trace level.
    /// 
    /// The trace level determines which spans and events will be captured by this subscriber.
    /// Only spans and events with a level equal to or more severe than the specified level 
    /// will be recorded.
    /// 
    /// # Parameters
    /// 
    /// * `trace_level` - The minimum severity level to capture
    /// 
    /// # Returns
    /// 
    /// A new `TracingSubscriber` configured to the specified trace level
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// // Create a subscriber that captures Info level and above
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// // Use the subscriber in a tracing context
    /// tracing::subscriber::with_default(subscriber, || {
    ///     // Traced code here
    /// });
    /// ```
    pub fn new(trace_level: Level) -> Self {
        LEVEL_FILTER.with(|level_filter| *level_filter.borrow_mut() = trace_level.into());
        Self {}
    }

    /// Retrieves the metadata for a span with the given ID.
    /// 
    /// Span metadata contains information about the span's name, target, level, etc.
    /// 
    /// # Parameters
    /// 
    /// * `id` - The ID of the span to retrieve metadata for
    /// 
    /// # Returns
    /// 
    /// A reference to the static `Metadata` for the specified span
    /// 
    /// # Panics
    /// 
    /// This function will panic if no span with the given ID exists
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// tracing::subscriber::with_default(subscriber.clone(), || {
    ///     let span = tracing::info_span!("test_span").entered();
    ///     // The first span created will have ID 1
    ///     let metadata = subscriber.get_span_metadata(1);
    ///     assert_eq!(metadata.name(), "test_span");
    /// });
    /// ```
    pub fn get_span_metadata(&self, id: u64) -> &'static Metadata<'static> {
        SPAN_METADATA.with(
            |span_metadata: &RefCell<HashMap<u64, &Metadata<'static>>>| -> &Metadata<'static> {
                span_metadata
                    .borrow()
                    .get(&id)
                    .unwrap_or_else(|| panic!("Failed to get span metadata ID {}", id))
            },
        )
    }

    /// Retrieves the JSON representation of a span with the given ID.
    /// 
    /// # Parameters
    /// 
    /// * `id` - The ID of the span to retrieve
    /// 
    /// # Returns
    /// 
    /// A `Value` containing the JSON representation of the span
    /// 
    /// # Panics
    /// 
    /// This function will panic if no span with the given ID exists
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// tracing::subscriber::with_default(subscriber.clone(), || {
    ///     let span = tracing::info_span!("test_span", value = 42).entered();
    ///     // The first span created will have ID 1
    ///     let span_json = subscriber.get_span(1);
    ///     // Now we can analyze the span data
    ///     // span_json will contain the span's ID, attributes, etc.
    /// });
    /// ```
    pub fn get_span(&self, id: u64) -> Value {
        SPANS.with(|spans| {
            spans
                .borrow()
                .get(&id)
                .unwrap_or_else(|| panic!("Failed to get span ID {}", id))
                .clone()
        })
    }

    /// Retrieves all events captured by this subscriber.
    /// 
    /// # Returns
    /// 
    /// A vector of `Value` objects, each containing the JSON representation of an event
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// tracing::subscriber::with_default(subscriber.clone(), || {
    ///     tracing::info!("Event 1");
    ///     tracing::error!("Event 2");
    ///     
    ///     let events = subscriber.get_events();
    ///     assert_eq!(events.len(), 2);
    /// });
    /// ```
    pub fn get_events(&self) -> Vec<Value> {
        EVENTS.with(|events| events.borrow().clone())
    }

    /// Processes the captured trace records with a provided function and then clears the events.
    /// 
    /// This is a convenient way to examine all captured spans and events in a single call.
    /// 
    /// # Parameters
    /// 
    /// * `f` - A function that takes references to the spans and events collections
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// tracing::subscriber::with_default(subscriber.clone(), || {
    ///     let span = tracing::info_span!("test_span").entered();
    ///     tracing::info!("Test event");
    ///     
    ///     subscriber.test_trace_records(|spans, events| {
    ///         assert_eq!(spans.len(), 1);
    ///         assert_eq!(events.len(), 1);
    ///     });
    ///     
    ///     // Events are cleared after the call
    ///     assert_eq!(subscriber.get_events().len(), 0);
    /// });
    /// ```
    pub fn test_trace_records<F: Fn(&HashMap<u64, Value>, &Vec<Value>)>(&self, f: F) {
        SPANS.with(|spans| {
            EVENTS.with(|events| {
                f(&spans.borrow().clone(), &events.borrow().clone());
                events.borrow_mut().clear();
            });
        });
    }

    /// Clears all captured spans and events, resetting the subscriber state.
    /// 
    /// This is useful for setting up a clean state before capturing traces for a specific test.
    /// 
    /// # Example
    /// 
    /// ```
    /// use hyperlight_testing::tracing_subscriber::TracingSubscriber;
    /// use tracing::Level;
    /// use tracing_core::Subscriber;
    /// 
    /// let subscriber = TracingSubscriber::new(Level::INFO);
    /// 
    /// tracing::subscriber::with_default(subscriber.clone(), || {
    ///     // Generate some spans and events
    ///     tracing::info!("Test event");
    ///     
    ///     // Clear everything before the actual test
    ///     subscriber.clear();
    ///     
    ///     // Now we have a clean state
    ///     assert_eq!(subscriber.get_events().len(), 0);
    /// });
    /// ```
    pub fn clear(&self) {
        SPANS.with(|spans| spans.borrow_mut().clear());
        EVENTS.with(|events| events.borrow_mut().clear());
        SPAN_STACK.with(|span_stack| span_stack.borrow_mut().clear());
        SPAN_METADATA.with(|span_metadata| span_metadata.borrow_mut().clear());
        NEXT_ID.with(|next_id| *next_id.borrow_mut() = 1);
    }
}

impl Subscriber for TracingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        LEVEL_FILTER.with(|level_filter| metadata.level() <= &*level_filter.borrow())
    }

    fn new_span(&self, span_attributes: &Attributes<'_>) -> Id {
        let span_id = NEXT_ID.with(|next_id| {
            let id = *next_id.borrow();
            *next_id.borrow_mut() += 1;
            id
        });
        let id = Id::from_u64(span_id);
        let json = json!({
        "span": {
            "id": id.as_serde(),
            "attributes": span_attributes.as_serde(),

        }});
        println!(
            "Thread {:?} {}",
            std::thread::current().id(),
            to_string_pretty(&json).expect("Failed to pretty print json")
        );
        SPANS.with(|spans| {
            spans.borrow_mut().insert(span_id, json);
        });
        let metadata = span_attributes.metadata();
        SPAN_METADATA.with(|span_metadata| {
            span_metadata.borrow_mut().insert(span_id, metadata);
        });
        id
    }

    fn record(&self, id: &Id, values: &Record<'_>) {
        let span_id = id.into_u64();
        SPANS.with(|spans| {
            let mut map = spans.borrow_mut();
            let entry = &mut *map
                .get_mut(&span_id)
                .unwrap_or_else(|| panic!("Failed to get span with ID {}", id.into_u64()));
            let json_object = entry
                .as_object_mut()
                .unwrap_or_else(|| panic!("Span entry is not an object {}", id.into_u64()));
            let mut json_values = json!(values.as_serde());
            println!(
                "Thread {:?} span {} values: {}",
                std::thread::current().id(),
                &span_id,
                to_string_pretty(&json_values).expect("Failed to pretty print json")
            );
            let json_values = json_values
                .as_object_mut()
                .expect("Record is not an object");
            json_object
                .get_mut("span")
                .expect("span not found in json")
                .as_object_mut()
                .expect("span was not an object")
                .get_mut("attributes")
                .expect("attributes not found in json")
                .as_object_mut()
                .expect("attributes was not an object")
                .append(json_values);
            println!(
                "Thread {:?} Updated Span {} values: {}",
                std::thread::current().id(),
                &span_id,
                to_string_pretty(&json_object).expect("Failed to pretty print json")
            );
        });
    }

    fn event(&self, event: &Event<'_>) {
        let json = json!({
            "event": event.as_serde(),
        });
        println!(
            "Thread {:?} {}",
            std::thread::current().id(),
            to_string_pretty(&json).expect("Failed to pretty print json")
        );
        EVENTS.with(|events| {
            events.borrow_mut().push(json);
        });
    }

    fn current_span(&self) -> Current {
        SPAN_STACK.with(|span_stack| {
            let stack = span_stack.borrow();
            if stack.is_empty() {
                return Current::none();
            }
            let id = stack.last().expect("Failed to get last span from stack");
            let map = SPAN_METADATA.with(|span_metadata| span_metadata.borrow().clone());
            let metadata = *map
                .get(&id.into_u64())
                .unwrap_or_else(|| panic!("Failed to get span metadata ID {}", id.into_u64()));
            Current::new(id.clone(), metadata)
        })
    }

    fn enter(&self, span: &Id) {
        println!(
            "Thread {:?} Entered Span {}",
            std::thread::current().id(),
            span.into_u64()
        );
        SPAN_STACK.with(|span_stack| {
            let mut stack = span_stack.borrow_mut();
            stack.push(span.clone());
        });
    }

    fn exit(&self, span: &Id) {
        println!(
            "Thread {:?} Exited Span {}",
            std::thread::current().id(),
            span.into_u64()
        );
        SPAN_STACK.with(|span_stack| {
            let mut stack = span_stack.borrow_mut();
            let popped = stack.pop();
            assert_eq!(popped, Some(span.clone()));
        });
    }

    // We are not interested in this method for testing

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
}
