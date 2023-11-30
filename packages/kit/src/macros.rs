#[macro_export]
macro_rules! prepare_entry_point {
    ($name:ident) => {
        #[no_mangle]
        pub fn prepare() {
            $name(OBIDecode::try_from_slice(&oei::get_calldata()).unwrap());
        }
    };
}

#[macro_export]
macro_rules! execute_entry_point {
    ($name:ident) => {
        #[no_mangle]
        pub fn execute() {
            oei::save_return_data(
                &$name(OBIDecode::try_from_slice(&oei::get_calldata()).unwrap())
                    .try_to_vec()
                    .unwrap(),
            );
        }
    };
}

#[macro_export]
macro_rules! prepare_abi_entry_point {
    ($name:ident) => {
        #[no_mangle]
        pub fn prepare() {
            $name(SolValue::abi_decode(&oei::get_calldata(), true).unwrap());
        }
    };
}

#[macro_export]
macro_rules! execute_abi_entry_point {
    ($name:ident) => {
        #[no_mangle]
        pub fn execute() {
            oei::save_return_data(
                &$name(SolValue::abi_decode(&oei::get_calldata(), true).unwrap()).abi_encode(),
            );
        }
    };
}
