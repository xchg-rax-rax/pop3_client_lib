use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

// TODO: Split this giant file into smaller sub modules
// TODO: Write a comprehensive test suite

// Structured representation of a email message
pub struct Message {
    headers: HashMap<String, String>,
    body: Vec<String>,
}

// Represents most important metadata of an email
pub struct MessageInfo {
    maildrop_number: u32,
    size: u32,
    origination_date: String,
    from: String,
    to: Option<String>,
    cc: Option<String>,
    bcc: Option<String>,
    subject: Option<String>,
}

impl MessageInfo {
    fn new(
        maildrop_number: u32,
        size: u32,
        headers: HashMap<String, String>
    ) -> Result<Self, String> {
        // Required Headers
        let origination_date: String = match headers.get("Date") {
            Some(origination_date) => origination_date.clone(),
            None => {
                return Err("Date field missing from headers".to_string());
            }
        };
        let from: String = match headers.get("From") {
            Some(from) => from.clone(),
            None => {
                return Err("From field missing from headers".to_string());
            }
        };
        // Optional Headers
        let to: Option<String> = match headers.get("To") {
            Some(to) => Some(to.clone()),
            None => None
        };
        let cc: Option<String> = match headers.get("Cc") {
            Some(cc) => Some(cc.clone()),
            None => None
        };
        let bcc: Option<String> = match headers.get("Bcc") {
            Some(bcc) => Some(bcc.clone()),
            None => None
        };
        let subject: Option<String> = match headers.get("Subject") {
            Some(subject) => Some(subject.clone()),
            None => None
        };

        let message_info: Self = MessageInfo {
            maildrop_number,
            size,
            origination_date,
            from,
            to,
            cc,
            bcc,
            subject
        };

        return Ok(message_info);
    }
}

// Object for managing a series of sessions with a single POP3 server
pub struct POP3Client {
    hostname: String,
    port: u32,
}

impl POP3Client {
    pub fn new(hostname: String, port: u32) -> Self {
        return POP3Client{
            hostname,
            port,
        };
    }

    pub fn new_session(&self) -> Result<POP3ClientSession, String> {
        let full_address = format!("{}:{}", self.hostname, self.port);
        let session_connection: TcpStream = match TcpStream::connect(full_address) {
            Ok(session_connection) => session_connection,
            Err(e) => {
                return Err(format!("Failed to connect to POP3 server:\n{:?}", e));
            }
        };
        // Sleep for a second to allow the server to respond
        std::thread::sleep(std::time::Duration::from_secs(1));
        let session: POP3ClientSession = match POP3ClientSession::new(session_connection) {
            Ok(session) => session,
            Err(e) => {
                return Err(format!("[!] Failed to initialize session:\n{:?}", e));
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
pub struct POP3ClientSession {
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
        let regex = regex::Regex::new(r"(<[^>]*>)").unwrap();
        let captures = match regex.captures(greeting) {
            Some(captures) => captures,
            None => {
                // No string is msg-id present
                return Ok(None);
            }
        };
        let msg_id: String = match captures.get(1) {
            Some(msg_id_match) => msg_id_match.as_str().to_string(),
            None => {
                return Err("Found msg-id but could not capture it?".to_string());
            }
        };
        return Ok(Some(msg_id));
    }

    pub fn login(
        &mut self, 
        username: &String,
        password: &String,
    ) -> Result<bool, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return self.login_impl(username, password);
            },
            POP3ClientSessionStates::Transaction => {
                return Err("Cannot login, session is already logged in".to_string());
            }
            POP3ClientSessionStates::Done => {
                return Err("Cannot login, session has terminated".to_string());
            }
        }
    }

    fn login_impl(
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

    pub fn apop_login(
            &mut self, 
            username: &String,
            password: &String,
    ) -> Result<bool, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return self.apop_login_impl(username, password);
            },
            POP3ClientSessionStates::Transaction => {
                return Err("Cannot login, session is already logged in".to_string());
            }
            POP3ClientSessionStates::Done => {
                return Err("Cannot login, session has terminated".to_string());
            }
        }
    }

    fn apop_login_impl(
            &mut self, 
            username: &String,
            password: &String,
    ) -> Result<bool, String> {
        let digest: String = match self.generate_apop_digest(password) {
            Ok(digest) => digest,
            Err(e) => {
                return Err(format!("Failed to generate APOP digest:\n{:?}", e));
            }
        };
        let (result, _) = match self.session_api.apop(
            username,
            &digest,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute APOP command:\n{:?}", e));
            }
        };
        if !result {
            return Ok(false);
        }
        return Ok(true);
    }

    fn generate_apop_digest(&self, password: &String) -> Result<String, String> {
        let msg_id  = match &self.msg_id {
            Some(msg_id) => msg_id.clone(),
            None => {
                return Err(
                    "No msg-id was sent, APOP authentication is not possible."
                    .to_string(),
                );
            }
        };
        let login_string: String = format!(
            "{}{}",
            msg_id,
            password,
        );
        let digest_bytes = md5::compute(login_string.as_bytes());
        let digest= format!("{:x}", digest_bytes);
        return Ok(digest);
    }

    // Get number of messages in maildrop
    pub fn get_number_of_messages(&mut self) -> Result<u32, String> {
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
                            format!("Failed to get maildrop details\n{:?}", e),
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

    // Get size of maildrop in bytes
    pub fn get_size_of_maildrop(&mut self) -> Result<u32, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get size of maildrop, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                match self.get_stat_details() {
                    Ok((_, size_of_maildrop)) => {
                        return Ok(size_of_maildrop);
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
                    "Cannot get size of maildrop, session has terminated".to_string(),
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
            r"^(\d+) (\d+)\r\n$",
        ).unwrap();
        let captures = match regular_expression.captures(
            response_body.as_str(),
        ) {
            Some(captures) => captures,
            None => {
                return Err(format!("Failed to parse STAT command response"));
            }
        };
        let number_of_messages: u32 = match captures[0].parse() {
            Ok(number_of_messages) => number_of_messages,
            Err(e) => {
                return Err(format!("Could not parse number of messages:\n{:?}", e));
            }
        };
        let size_of_maildrop: u32 = match captures[1].parse() {
            Ok(size_of_maildrop) => size_of_maildrop,
            Err(e) => {
                return Err(format!("Could not parse size of maildrop:\n{:?}", e));
            }
        };
        return Ok((number_of_messages, size_of_maildrop));
    }


    pub fn get_maildrop_info(&mut self) -> Result<Vec<MessageInfo>, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get maildrop info, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.retirve_maildrop_info();
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get maildrop info, session has terminated".to_string(),
                );
            }
        }
    }

    fn retirve_maildrop_info(&mut self) -> Result<Vec<MessageInfo>, String> {
        // get list info
        let list_info: Vec<(u32, u32)> = match self.get_list() {
            Ok(list_info) => list_info,
            Err(e) => {
                return Err(format!("Could not get list info:\n{:?}", e));
            }
        };

        let mut message_info_list: Vec<MessageInfo> = Vec::new();
        for (message_number, message_size) in list_info {
            // Get headers
            let message_headers: HashMap<String, String> = match self.get_message_headers(
                message_number,
            ) {
                Ok(message_headers) => message_headers,
                Err(e) => {
                    return Err(
                        format!(
                            "Could not get headers for message {}:\n{:?}",
                            message_number,
                            e,
                        ),
                    );
                }
            };

            let message_info: MessageInfo = match MessageInfo::new(
                message_number,
                message_size,
                message_headers,
            ) {
                Ok(message_headers) => message_headers,
                Err(e) => {
                    return Err(
                        format!(
                            "Failed to initialize message info for message {}:\n{:?}",
                            message_number,
                            e,
                        ),
                    );
                }
            };
            message_info_list.push(message_info);
        }
        return Ok(message_info_list);
    }

    fn get_message_headers(
        &mut self,
        message_number: u32,
    ) -> Result<HashMap<String, String>, String> {
        let (result, response_body) =  match self.session_api.top(
            message_number,
            0,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute TOP command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("TOP command returned error:\n{:?}", response_body));
        }

        let headers = match POP3ClientSession::parse_headers(
            &response_body
        ) {
            Ok(headers ) => headers,
            Err(e) => {
                return Err(format!("Could not parse headers:\n{:?}", e));
            }
        };

        return Ok(headers);
    }

    fn parse_headers(raw_response_headers: &String) -> Result<HashMap<String, String>, String> {
        let raw_headers : Vec<&str> = raw_response_headers.split("\r\n").collect();

        let mut parsed_headers: HashMap<String, String> = HashMap::new();
        for raw_header in raw_headers {
            let regular_expression: regex::Regex = regex::Regex::new(
                r"^([^:])\s*(.*)$",
            ).unwrap();
            let captures = match regular_expression.captures(
                raw_header,
            ) {
                Some(captures) => captures,
                None => {
                    return Err(format!("Failed to parse header:\n{}", raw_header));
                }
            };
            let field_name: String = match captures[0].parse() {
                Ok(field_name) => field_name,
                Err(e) => {
                    return Err(format!("Could not field name:\n{:?}", e));
                }
            };
            let field_value: String = match captures[1].parse() {
                Ok(field_value) => field_value,
                Err(e) => {
                    return Err(format!("Could not field value:\n{:?}", e));
                }
            };
            parsed_headers.insert(field_name, field_value);
        }
        return Ok(parsed_headers);
    }

    fn get_list(&mut self) -> Result<Vec<(u32, u32)>, String> {
        let (result, response_body) = match self.session_api.list(
            None,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute LIST command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("LIST command returned error:\n{:?}", response_body));
        }

        let response_body_lines: Vec<&str> = response_body.split("\r\n").collect();
        
        let mut parsed_list_response: Vec<(u32, u32)> = Vec::new();
        for response_body_line in response_body_lines.iter().skip(1) {
            let parsed_line: (u32, u32) = match POP3ClientSession::parse_list_line(
                response_body_line,
            ) {
                Ok(parsed_line) => parsed_line,
                Err(e) => {
                    return Err(format!("Failed to parse LIST line:\n{:?}", e));
                }
            };
            parsed_list_response.push(parsed_line);
        }
        return Ok(parsed_list_response);
    }

    fn parse_list_line(list_line: &str) -> Result<(u32, u32), String> {
        let regular_expression: regex::Regex = regex::Regex::new(
            r"^(\d+) (\d+)$",
        ).unwrap();
        let captures = match regular_expression.captures(
            list_line,
        ) {
            Some(captures) => captures,
            None => {
                return Err(format!("LIST response line regex failed:\n{:?}", list_line));
            }
        };
        let message_number: u32 = match captures[0].parse() {
            Ok(message_number) => message_number,
            Err(e) => {
                return Err(format!("Could not parse messages number:\n{:?}", e));
            }
        };
        let size_of_message: u32 = match captures[1].parse() {
            Ok(size_of_message) => size_of_message,
            Err(e) => {
                return Err(format!("Could not parse size of message:\n{:?}", e));
            }
        };

        return Ok((message_number, size_of_message));
    }

    pub fn get_message(&mut self, message_number: u32) -> Result<Message, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get message, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.retrive_message(message_number);
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get message, session has terminated".to_string(),
                );
            }
        }
    }

    fn retrive_message(
        &mut self,
        message_number: u32,
    ) -> Result<Message, String> {
        let (result, raw_response) = match self.session_api.retr(
            message_number,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute RETR command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("RETR command returned error:\n{}", raw_response));
        }
        
        let sections: Vec<&str> = raw_response.split("\r\n\r\n").collect();
        let header_section = match sections.get(0) {
            Some(header_section ) => *header_section,
            None => {
                return Err("Header section not present".to_string());
            }
        };
        let body_section = match sections.get(1) {
            Some(body_section ) => *body_section,
            None => {
                return Err("Body section not present".to_string());
            }
        };

        let headers = match POP3ClientSession::parse_headers(
            &header_section.to_string(),
        ) {
            Ok(headers) => headers,
            Err(e) => {
                return Err(format!("Could not parse headers:\n{:?}", e));
            }
        };
        
        let mut unprocessed_body: Vec<&str> = body_section.split("\r\n").collect();

        // Check for then remove termination line
        let last_line: &str = match unprocessed_body.last() {
            Some(last_line) => *last_line,
            None => {
                return Err("Body contains no lines".to_string());
            }
        };
        if last_line != "." {
            return Err("Message lacks termination character".to_string());
        }
        unprocessed_body = unprocessed_body[..unprocessed_body.len() - 1].to_vec();

        let body: Vec<String> = unprocessed_body
            .iter()
            .map(|x| POP3ClientSession::remove_byte_stuffing(*x))
            .collect();
        
        let message: Message  = Message {
            headers,
            body
        };
        return Ok(message);
    }

    fn remove_byte_stuffing(line: &str) -> String{
        let byte_stuffing_regex: regex::Regex = regex::Regex::new(r"^\.\.").unwrap();
        let replaced: String = byte_stuffing_regex
            .replace(line, ".")
            .into_owned();
        return replaced;
    }

    pub fn get_maildrop(&mut self) -> Result<Vec<Message>, String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get maildrop, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.get_maildrop_impl();
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get maildrop, session has terminated".to_string(),
                );
            }
        }
    }

    fn get_maildrop_impl(&mut self) -> Result<Vec<Message>, String> {
        let message_list_entries: Vec<(u32, u32)> = match self.get_list() {
            Ok(message_list) => message_list,
            Err(e) => {
                return Err(format!("Failed to get message list:\n{:?}", e));
            }
        };

        let mut messages: Vec<Message> = Vec::new();
        for (message_number, _) in message_list_entries {
            let message: Message = match self.retrive_message(message_number) {
                Ok(message) => message,
                Err(e) => {
                    return Err(format!("Failed to retrieve message:\n{:?}", e));
                }
            };
            messages.push(message);
        }
        return Ok(messages);
    }

    pub fn delete_message(&mut self, message_number: u32) -> Result<(), String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get delete message, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.delete_message_impl(message_number);
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get delete message, session has terminated".to_string(),
                );
            }
        }
    }

    fn delete_message_impl(&mut self, message_number: u32) -> Result<(), String> {
        let (result, response_body) = match self.session_api.dele(message_number) {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute DELE command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("DELE command returned error:\n{}", response_body));
        }

        return Ok(());
    }

    pub fn reset_deleted_messages(&mut self) -> Result<(), String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot get reset deleted message, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.reset_deleted_messages_impl();
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot get reset deleted message, session has terminated".to_string(),
                );
            }
        }
    }

    fn reset_deleted_messages_impl(&mut self) -> Result<(), String> {
        let (result, response_body) = match self.session_api.rset() {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute RSET command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("RSET command returned error:\n{}", response_body));
        }

        return Ok(());
    }

    pub fn quit(&mut self) -> Result<(), String> {
        match self.state {
            POP3ClientSessionStates::Authorization => {
                return Err(
                    "Cannot quit, session must be logged in".to_string(),
                );
            },
            POP3ClientSessionStates::Transaction => {
                return self.quit_impl();
            }
            POP3ClientSessionStates::Done => {
                return Err(
                    "Cannot quit, session has terminated".to_string(),
                );
            }
        }
    }

    fn quit_impl(&mut self) -> Result<(), String> {
        let (result, response_body) = match self.session_api.quit() {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(format!("Could not execute QUIT command:\n{:?}", e));
            }
        };
        if !result {
            return Err(format!("QUIT command returned error:\n{}", response_body));
        }
        self.state = POP3ClientSessionStates::Done;
        return Ok(());
    }
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
        
        // Sleep for a second to allow the server to respond
        std::thread::sleep(std::time::Duration::from_secs(1));

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

    fn list(
        &mut self,
        message_number: Option<u32>,
    ) -> Result<(bool, String), String> {
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
