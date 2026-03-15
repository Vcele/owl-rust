// Circular buffer implementation

/// A circular buffer that can hold `capacity` items.
/// When the buffer is full, new items overwrite the oldest item.
pub struct CircularBuf<T> {
    buffer: Vec<Option<T>>,
    head: usize,
    tail: usize,
    full: bool,
}

impl<T> CircularBuf<T> {
    /// Create a new circular buffer with the given capacity
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");
        let mut buffer = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buffer.push(None);
        }
        CircularBuf {
            buffer,
            head: 0,
            tail: 0,
            full: false,
        }
    }

    /// Number of elements currently stored in the buffer
    pub fn len(&self) -> usize {
        if self.full {
            self.buffer.len()
        } else if self.head >= self.tail {
            self.head - self.tail
        } else {
            self.buffer.len() + self.head - self.tail
        }
    }

    /// Maximum number of elements the buffer can hold
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer contains no elements
    pub fn is_empty(&self) -> bool {
        !self.full && self.head == self.tail
    }

    /// Whether the buffer is at capacity
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Reset the buffer to empty state. Does not clear data.
    pub fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.full = false;
    }

    /// Push an item into the buffer, overwriting the oldest item if full.
    pub fn push(&mut self, item: T) {
        if self.full {
            // Overwrite oldest (advance tail)
            self.tail = (self.tail + 1) % self.buffer.len();
        }
        self.buffer[self.head] = Some(item);
        self.head = (self.head + 1) % self.buffer.len();
        self.full = self.head == self.tail;
    }

    /// Try to push an item. Returns `Err(item)` if the buffer is full.
    pub fn try_push(&mut self, item: T) -> Result<(), T> {
        if self.full {
            return Err(item);
        }
        self.buffer[self.head] = Some(item);
        self.head = (self.head + 1) % self.buffer.len();
        self.full = self.head == self.tail;
        Ok(())
    }

    /// Remove and return the oldest item, or `None` if empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let item = self.buffer[self.tail].take();
        self.tail = (self.tail + 1) % self.buffer.len();
        self.full = false;
        item
    }

    /// Peek at the oldest item without removing it.
    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            self.buffer[self.tail].as_ref()
        }
    }
}
