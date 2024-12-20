use cosmwasm_std::{Api, Response};

pub struct GasTracker<'a> {
    logs: Vec<(String, String)>,
    api: &'a dyn Api,
}

impl<'a> GasTracker<'a> {
    pub fn new(api: &'a dyn Api) -> Self {
        Self {
            logs: Vec::new(),
            api,
        }
    }

    pub fn group<'b>(&'b mut self, name: &str) -> GasGroup<'a, 'b> {
        let mut group = GasGroup::new(self, name.to_string());
        group.mark();
        group
    }

    // pub fn from<'b>(&'b mut self, other: GasGroup<'b, 'b>) -> GasGroup<'a, 'b> {
    //     let mut group = GasGroup::new(self, other.name);
    //     group.index = other.index;
    //     group
    // }

    // pub fn from<'b>(&'b mut self, name: &str, index: usize) -> GasGroup<'a, 'b> {
    //     let mut group = GasGroup::new(self, name.to_string());
    //     group.index = index;
    //     group
    // }

    pub fn add_to_response(self, resp: Response) -> Response {
        let mut new_resp = resp.clone();
        for log in self.logs.into_iter() {
            new_resp = new_resp.add_attribute_plaintext(log.0, log.1);
        }
        new_resp
    }
}

pub trait LoggingExt {
    fn add_gas_tracker(&self, tracker: GasTracker) -> Response;
}

impl LoggingExt for Response {
    fn add_gas_tracker(&self, tracker: GasTracker) -> Response {
        tracker.add_to_response(self.to_owned())
    }
}

pub struct GasGroup<'a, 'b> {
    pub tracker: &'b mut GasTracker<'a>,
    pub name: String,
    pub index: usize,
}

impl<'a, 'b> GasGroup<'a, 'b> {
    fn new(tracker: &'b mut GasTracker<'a>, name: String) -> Self {
        Self {
            tracker,
            name,
            index: 0,
        }
    }

    pub fn mark(&mut self) {
        self.log("");
    }

    pub fn log(&mut self, comment: &str) {
        let gas = self.tracker.api.check_gas();
        let log_entry = (
            format!("gas.{}", self.name,),
            format!(
                "{}:{}:{}",
                self.index,
                gas.unwrap_or(0u64),
                comment
            ),
        );
        self.tracker.logs.push(log_entry);
        self.index += 1;
    }

    pub fn logf(&mut self, comment: String) {
        self.log(comment.as_str())
    }
}
