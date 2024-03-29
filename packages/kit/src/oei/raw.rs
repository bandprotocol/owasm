extern "C" {
    pub fn get_span_size() -> i64;
    pub fn get_ask_count() -> i64;
    pub fn get_min_count() -> i64;
    pub fn get_prepare_time() -> i64;
    pub fn get_execute_time() -> i64;
    pub fn get_ans_count() -> i64;
    pub fn read_calldata(offset: i64) -> i64;
    pub fn set_return_data(offset: i64, len: i64);
    pub fn ask_external_data(eid: i64, did: i64, offset: i64, len: i64);
    pub fn get_external_data_status(eid: i64, vid: i64) -> i64;
    pub fn read_external_data(eid: i64, vid: i64, offset: i64) -> i64;
    pub fn ecvrf_verify(
        y_offset: i64,
        y_len: i64,
        pi_offset: i64,
        pi_len: i64,
        alpha_offset: i64,
        alpha_len: i64,
    ) -> u32;
}
