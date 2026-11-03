use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VirtualTimeError {
    ScheduledInPast,
    SequenceOverflow,
}

pub(crate) struct VirtualTime<E> {
    now_ms: u64,
    next_sequence: u64,
    events: BTreeMap<(u64, u64), E>,
}

impl<E> VirtualTime<E> {
    pub(crate) fn new() -> Self {
        Self {
            now_ms: 0,
            next_sequence: 0,
            events: BTreeMap::new(),
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub(crate) fn schedule(&mut self, at_ms: u64, event: E) -> Result<(), VirtualTimeError> {
        if at_ms < self.now_ms {
            return Err(VirtualTimeError::ScheduledInPast);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(VirtualTimeError::SequenceOverflow)?;
        self.events.insert((at_ms, sequence), event);
        Ok(())
    }

    pub(crate) fn next(&mut self) -> Option<(u64, E)> {
        let (at_ms, sequence) = *self.events.first_key_value()?.0;
        let event = self.events.remove(&(at_ms, sequence))?;
        self.now_ms = at_ms;
        Some((at_ms, event))
    }
}
