/// This macro logs a message to the browser console using the `web_sys::console::log_1` function.
/// It takes any number of arguments and formats them into a string using the `format!` macro.
/// The resulting string is then passed to `web_sys::console::log_1` as an argument.
#[macro_export]
macro_rules! clog {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

/// This macro is a wrapper around the `clog!` and `println!` macros.
/// It logs a message to the console using `clog!` if the target architecture is `wasm32`,
/// or prints the message to the standard output using `println!` otherwise.
/// It takes any number of arguments and formats them into a string using the `format!` macro.
/// The resulting string is then passed to either `clog!` or `println!` as an argument,
/// depending on the target architecture.
#[macro_export]
macro_rules! log_to_console {
    ( $( $t:tt )* ) => {
        #[cfg(target_arch = "wasm32")]
        $crate::clog!( $( $t )* );
        #[cfg(not(target_arch = "wasm32"))]
        println!( $( $t )* );
    }
}
