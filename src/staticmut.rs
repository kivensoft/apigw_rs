//! static mut value

use std::mem::MaybeUninit;

pub struct StaticMut<T> {
    value: MaybeUninit<T>,
    #[cfg(debug_assertions)]
    inited: bool,
}

impl<T> StaticMut<T> {
    pub const fn new() -> Self {
        Self {
            value: MaybeUninit::uninit(),
            #[cfg(debug_assertions)]
            inited: false,
        }
    }

    pub fn init(&mut self, value: T) {
        #[cfg(debug_assertions)]
        {
            if self.inited {
                panic!("static mut value has already been initialized");
            }
            self.inited = true;
        }
        self.value.write(value);
    }

    pub fn get(&self) -> &T {
        #[cfg(debug_assertions)]
        {
            if !self.inited {
                panic!("statuc mut value has not been initialized");
            }
        }
        unsafe { self.value.assume_init_ref() }
    }
}
