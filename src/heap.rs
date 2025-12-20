pub struct Heap {
    pages: Vec<HeapPage>,
}

pub struct HeapPage {
    base: u64,
    end: u64,
}

impl Heap {
    pub fn new(pages: Vec<HeapPage>) -> Self {
        Self { pages }
    }

    pub fn add_page(&mut self, base: u64, end: u64) {
        self.pages.push(HeapPage::new(base, end));
    }

    pub fn reserve(&mut self, size: u64, alignment: u64) -> Option<u64> {
        for page in &mut self.pages {
            if let Some(addr) = page.reserve(size, alignment) {
                return Some(addr);
            }
        }

        None
    }

    pub fn reserve_with_same_alignment(&mut self, prev_va: u64, size: u64, max_alignment: Option<u64>) -> Option<u64> {
        for page in &mut self.pages {
            if let Some(addr) = page.reserve_with_same_alignment(prev_va, size, max_alignment) {
                return Some(addr);
            }
        }

        None
    }
}

impl HeapPage {
    pub fn new(base: u64, end: u64) -> Self {
        Self { base, end }
    }

    fn get_max_alignment(va: u64) -> u64 {
        if (va == 0) {
            return 0;
        }

        return va & va.wrapping_neg();
    }

    pub fn reserve(&mut self, size: u64, alignment: u64) -> Option<u64> {
        let aligned_base = (self.base + (alignment - 1)) & !(alignment - 1);

        if aligned_base + size > self.end {
            None
        } else {
            self.base = aligned_base + size;
            Some(aligned_base)
        }
    }

    pub fn reserve_with_same_alignment(&mut self, prev_va: u64, size: u64, max_alignment: Option<u64>) -> Option<u64> {
        let alignment = Self::get_max_alignment(prev_va).min(max_alignment.unwrap_or(0));
        self.reserve(size, alignment)
    }
}