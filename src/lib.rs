use std::{io::{Read, Write}, net::TcpStream};


// Object for managing a series of sessions with a single POP3 server
struct POP3Client {
    hostname: String,
    port: u32,
}

impl POP3Client {
    fn new_session(&self) -> Result<POP3ClientSession, String> {
        let full_address = format!("{}:{}", self.hostname, self.port);
        let session_connection: TcpStream = match TcpStream::connect(full_address) {
            Ok(session_connection) => session_connection,
            Err(e) => {
                return Err(format!("Failed to connect to POP3 server:\n{:?}", e));
            }
        };
        let session: POP3ClientSession = match POP3ClientSession::new(session_connection) {
            Ok(session) => session,
            Err(e) => {
                return Err(format!("Failed to initialize session:\n{:?}", e));
            }
        };
        return Ok(session);
    }
}

#[derive(PartialEq)]
enum POP3ClientSessionStates {
    Authorization,
    Transaction,
    Done,
}

// Object for managing interactions with a single connection with a POP3 server
struct POP3ClientSession {
    session_api: POP3ClientSessionAPI,
    msg_id: Option<String>,
    state: POP3ClientSessionStates
}

impl POP3ClientSession {
    fn new(session_connection: TcpStream) -> Result<Self, String> {
        let mut session_api: POP3ClientSessionAPI = POP3ClientSessionAPI {
            session_connection
        };
        let greeting: String= match POP3ClientSession::read_greeting(&mut session_api) {
            Ok(greeting) => greeting,
            Err(e) => {
                return Err(format!("Failed to read greeting:\n{:?}", e));
            }
        };
        let msg_id: Option<String> = match POP3ClientSession::parse_greeting(
            &greeting,
        ) {
            Ok(msg_id) => msg_id,
            Err(e) => {
                return Err(format!("Failed to parse greeting:\n{:?}", e));
            }
        };
        return Ok(POP3ClientSession {
            session_api,
            msg_id,
            state: POP3ClientSessionStates::Authorization,
        });
    }

    fn read_greeting(session_api: &mut POP3ClientSessionAPI) -> Result<String, String> {
        let mut raw_greeting: Vec<u8> = Vec::with_capacity(512);

        let bytes_read = match session_api.read_data(
            &mut raw_greeting,
        ) {
            Ok(bytes_read) => bytes_read,
            Err(e) => {
                return Err(format!("Failed to read data from connection:\n{:?}", e));
            }
        };
        if bytes_read == 0 {
            return Err("Server did not send a greeting".to_string());
        }

        let greeting = String::from_utf8_lossy(&raw_greeting)
            .trim_end_matches('\x00')
            .to_string();

        return Ok(greeting);
    }

    fn parse_greeting(greeting: &String) -> Result<Option<String>, String> {
        assert!(false);
        return Ok(Some("".to_string()));
    }

    pub fn login(
        &mut self, 
        username: &String,
        password: &String,
    ) -> Result<bool, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return self.authenticate(username, password);
            },
            POP3ClientSessionStates::Transaction => {
                return Err("Cannot login, session is already logged in".to_string());
            }
            POP3ClientSessionStates::Done => {
                return Err("Cannot login, session has terminated".to_string());
            }
        }
    }

    fn authenticate(
        &mut self,
        username: &String,
        password: &String,
    ) -> Result<bool, String> {
        // Perform user command and check result
        let (user_result, _) =  match self.session_api.user(username) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(
                    format!(
                        "An error occurred while handling the USER command:\n{}",
                        e,
                    ),
                );
            }
        };
        if !user_result {
            return Ok(false);
        }

        // Perform user command and check result
        let (pass_result, _) =  match self.session_api.pass(password) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(
                    format!(
                        "An error occurred while handling the PASS command:\n{}",
                        e,
                    ),
                );
            }
        };
        if !pass_result {
            return Ok(false);
        }
        self.state = POP3ClientSessionStates::Transaction;
        return Ok(true);
    }

    // Get number of messages in maildrop
    fn number_of_messages_in_mail_drop(&mut self) -> Result<u32, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get number of messages, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                match self.get_stat_details() {
                    Ok((number_of_messages, _)) => {
                        return Ok(number_of_messages);
                    },
                    Err(e) => {
                        return Err(
                            format!("Failed to get maildrop details\n{e}"),
                        );
                    }
                }
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get number of messages, session has terminated".to_string(),
                );
            }
        }
    }

    fn get_stat_details(&mut self) -> Result<(u32, u32), String> {
        let (result, response_body) = match self.session_api.stat() {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to run STAT command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("STAT command returned error:\n{}", response_body));
        }
        let regular_expression: regex::Regex = regex::Regex::new(
            r"^(\d*) (\d*)\r\n$",
        ).unwrap();
        let captures = match regular_expression.captures(
            response_body.as_str(),
        ) {
            Some(captures) => captures,
            None => {
                return Err(format!("Failed to parse STAT command response"));
            }
        };
    }
    
    
    // Get total maildrop size
    
    //
}

// Object for managing low level interactions with the server
struct POP3ClientSessionAPI {
    session_connection: TcpStream
}

impl POP3ClientSessionAPI {
    fn read_data(&mut self, output_buffer: &mut Vec<u8>) -> Result<usize, String> {
        let bytes_read: usize = match self.session_connection.read(output_buffer) {
            Ok(bytes_read) => bytes_read,
            Err(e) => {
                return Err(format!("Failed to read bytes:\n{:?}", e));
            }
        };
        return Ok(bytes_read);
    }

    fn read_string(&mut self) -> Result<String, String> {
        let mut raw_response: Vec<u8> = Vec::with_capacity(4096);
        match self.read_data(
            &mut raw_response,
        ) {
            Ok(bytes_read) => bytes_read,
            Err(e) => {
                return Err(format!("Failed to read data from connection:\n{:?}", e));
            }
        };
        let response: String = String::from_utf8_lossy(&raw_response)
            .trim_end_matches('\x00')
            .to_string();
        return  Ok(response);
    }

    fn send_data(&mut self, input_buffer: &[u8]) -> Result<usize, String> {
        let bytes_written = match self.session_connection.write(&input_buffer) {
            Ok(bytes_written) => bytes_written ,
            Err(e) => {
                return Err(format!("Failed to write bytes:\n{:?}", e));
            }
        };
        return Ok(bytes_written);
    }

    fn execute_command(&mut self, command: &String) 
        -> Result<(bool, String), String>
    {
        let bytes_written: usize = match self.send_data(command.as_bytes()) {
            Ok(bytes_written) => bytes_written,
            Err(e) => {
                return Err(format!("Failed to send command:\n{:?}", e));
            }
        };
        if bytes_written == 0 {
            return Err(format!("Failed to send any data to the server"));
        }
        let response = match self.read_string() {
            Ok(response ) => response ,
            Err(e) => {
                return Err(format!("Failed to read response:\n{:?}", e));
            }
        };
        if response.starts_with("+0K") {
            let response_body = match response.split("+OK").nth(1) {
                Some(response_body) => response_body.to_string(),
                None => "".to_string(),
            };
            return Ok((true, response_body));
        } 
        else if response.starts_with("-ERR") {
            let response_body = match response.split("-ERR").nth(1) {
                Some(response_body) => response_body.to_string(),
                None => "".to_string(),
            };
            return Ok((false, response_body.to_string()));
        }
        else {
            return Err(format!("Unexpected response returned:\n{}", response));
        }
    }

    fn user(&mut self, username: &String) -> Result<(bool, String), String> {
        let command: String = format!("USER {}\r\n", username);
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn pass(&mut self, password: &String) -> Result<(bool, String), String> {
        let command: String = format!("PASS {}\r\n", password);
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn apop(&mut self, username: &String, digest: &String) -> Result<(bool, String), String> {
        let command: String = format!("APOP {} {}\r\n", username, digest);
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn noop(&mut self) -> Result<(bool, String), String> {
        let command: String = format!("NOOP\r\n");
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn dele(&mut self, message_number: u32) -> Result<(bool,String), String> {
        let command: String = format!("DELE {}\r\n", message_number);
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn rset(&mut self) -> Result<(bool, String), String> {
        let command: String = format!("RSET\r\n");
        let (result, response_body)= match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn quit(&mut self) -> Result<(bool, String), String> {
        let command: String = format!("QUIT\r\n");
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn stat(&mut self) -> Result<(bool, String), String> {
        let command: String = "STAT\r\n".to_string();
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn list(&mut self, message_number: Option<u32>) -> Result<(bool, String), String> {
        let command: String = match message_number {
            Some(message_number) => format!("LIST {}\r\n", message_number),
            None => "LIST\r\n".to_string()
        };
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn retr(&mut self, message_number: u32) -> Result<(bool, String), String> {
        let command: String = format!("RETR {}\r\n", message_number);
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn top(
        &mut self, 
        message_number: u32,
        number_of_lines: u32,
    ) -> Result<(bool, String), String> {
        let command: String = format!(
            "TOP {} {}\r\n",
            message_number,
            number_of_lines,
        );
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }

    fn uidl(&mut self, message_number: Option<u32>) -> Result<(bool, String), String> {
        let command: String = match message_number {
            Some(message_number) => format!("UIDL {}\r\n", message_number),
            None => "UIDL\r\n".to_string()
        };
        let (result, response_body) = match self.execute_command(&command) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Failed to execute command:\n{:?}", e));
            }
        };
        return Ok((result, response_body));
    }
}
use std::{io::{Read, Write}, net::TcpStream};
