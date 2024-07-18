#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Alumni {
    id: u64,
    name: String,
    email: String,
    graduation_year: u32,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Association {
    id: u64,
    name: String,
    description: String,
    alumnis: Vec<u64>,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Event {
    id: u64,
    association_id: u64,
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer: String,
    capacity: u32,
    attendees: Vec<String>,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct MessageToAssociation {
    id: u64,
    association_id: u64,
    sender_id: u64,
    content: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct MentorshipRequest {
    id: u64,
    requester_id: u64,
    mentor_id: u64,
    status: String,
    created_at: u64,
}

impl Storable for Alumni {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Alumni {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Association {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Association {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Event {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Event {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for MessageToAssociation {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for MessageToAssociation {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for MentorshipRequest {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for MentorshipRequest {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static ALUMNI_STORAGE: RefCell<StableBTreeMap<u64, Alumni, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static ASSOCIATIONS_STORAGE: RefCell<StableBTreeMap<u64, Association, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static EVENTS_STORAGE: RefCell<StableBTreeMap<u64, Event, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static MESSAGES_STORAGE: RefCell<StableBTreeMap<u64, MessageToAssociation, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static MENTORSHIP_REQUESTS_STORAGE: RefCell<StableBTreeMap<u64, MentorshipRequest, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AlumniPayload {
    name: String,
    email: String,
    graduation_year: u32,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct SearchAlumniPayload {
    name: Option<String>,
    graduation_year: Option<u32>,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AssociationPayload {
    name: String,
    description: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct JoinAssociationPayload {
    alumni_id: u64,
    association_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct LeaveAssociationPayload {
    alumni_id: u64,
    association_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct EventPayload {
    association_id: u64,
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer: String,
    capacity: u32,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct RsvpEventPayload {
    alumni_id: u64,
    event_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MessagePayload {
    association_id: u64,
    sender_id: u64,
    content: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MentorshipRequestPayload {
    requester_id: u64,
    mentor_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
    UnAuthorized(String),
}

#[ic_cdk::update]
fn create_alumni(payload: AlumniPayload) -> Result<Alumni, Message> {
    if payload.name.is_empty() || payload.email.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' and 'email' are provided.".to_string(),
        ));
    }

    let id = increment_id_counter()?;

    let alumni = Alumni {
        id,
        name: payload.name,
        email: payload.email,
        graduation_year: payload.graduation_year,
        created_at: current_time(),
    };
    ALUMNI_STORAGE.with(|storage| storage.borrow_mut().insert(id, alumni.clone()));
    Ok(alumni)
}

#[ic_cdk::query]
fn get_alumnis() -> Result<Vec<Alumni>, Message> {
    ALUMNI_STORAGE.with(|storage| {
        let alumni: Vec<Alumni> = storage
            .borrow()
            .iter()
            .map(|(_, alumni)| alumni.clone())
            .collect();

        if alumni.is_empty() {
            Err(Message::NotFound("No alumni found".to_string()))
        } else {
            Ok(alumni)
        }
    })
}

#[ic_cdk::query]
fn get_alumni_by_id(id: u64) -> Result<Alumni, Message> {
    ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, alumni)| alumni.id == id)
            .map(|(_, alumni)| alumni.clone())
            .ok_or(Message::NotFound("Alumni not found".to_string()))
    })
}

#[ic_cdk::update]
fn create_association(payload: AssociationPayload, user_id: u64) -> Result<Association, Message> {
    authenticate_user(user_id)?;

    if payload.name.is_empty() || payload.description.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' and 'description' are provided.".to_string(),
        ));
    }

    let id = increment_id_counter()?;

    let association = Association {
        id,
        name: payload.name,
        description: payload.description,
        alumnis: vec![],
        created_at: current_time(),
    };
    ASSOCIATIONS_STORAGE.with(|storage| storage.borrow_mut().insert(id, association.clone()));
    Ok(association)
}

#[ic_cdk::update]
fn update_association(id: u64, payload: AssociationPayload, user_id: u64) -> Result<Association, Message> {
    authenticate_user(user_id)?;

    ASSOCIATIONS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut association) = storage.get(&id) {
            if !payload.name.is_empty() {
                association.name = payload.name;
            }
            if !payload.description.is_empty() {
                association.description = payload.description;
            }
            storage.insert(id, association.clone());
            Ok(association)
        } else {
            Err(Message::NotFound("Association not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_association(id: u64, user_id: u64) -> Result<Message, Message> {
    authenticate_user(user_id)?;

    ASSOCIATIONS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Association deleted.".to_string()))
        } else {
            Err(Message::NotFound("Association not found".to_string()))
        }
    })
}

#[ic_cdk::query]
fn get_associations() -> Result<Vec<Association>, Message> {
    ASSOCIATIONS_STORAGE.with(|storage| {
        let associations: Vec<Association> = storage
            .borrow()
            .iter()
            .map(|(_, association)| association.clone())
            .collect();

        if associations.is_empty() {
            Err(Message::NotFound("No associations found".to_string()))
        } else {
            Ok(associations)
        }
    })
}

#[ic_cdk::query]
fn get_association_by_id(id: u64) -> Result<Association, Message> {
    ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == id)
            .map(|(_, association)| association.clone())
            .ok_or(Message::NotFound("Association not found".to_string()))
    })
}

#[ic_cdk::update]
fn create_event(payload: EventPayload, user_id: u64) -> Result<Event, Message> {
    authenticate_user(user_id)?;

    if payload.title.is_empty()
        || payload.description.is_empty()
        || payload.location.is_empty()
        || payload.organizer.is_empty()
    {
        return Err(Message::InvalidPayload(
            "Ensure 'title', 'description', 'location', and 'organizer' are provided.".to_string(),
        ));
    }

    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.association_id)
            .map(|assoc| assoc.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    if payload.capacity == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'capacity' is greater than 0.".to_string(),
        ));
    }

    let id = increment_id_counter()?;

    let event = Event {
        id,
        association_id: payload.association_id,
        title: payload.title,
        description: payload.description,
        date_time: payload.date_time,
        location: payload.location,
        organizer: payload.organizer,
        capacity: payload.capacity,
        attendees: vec![],
        created_at: current_time(),
    };
    EVENTS_STORAGE.with(|storage| storage.borrow_mut().insert(id, event.clone()));
    Ok(event)
}

#[ic_cdk::update]
fn update_event(id: u64, payload: EventPayload, user_id: u64) -> Result<Event, Message> {
    authenticate_user(user_id)?;

    EVENTS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut event) = storage.get(&id) {
            if !payload.title.is_empty() {
                event.title = payload.title;
            }
            if !payload.description.is_empty() {
                event.description = payload.description;
            }
            if !payload.location.is_empty() {
                event.location = payload.location;
            }
            if !payload.organizer.is_empty() {
                event.organizer = payload.organizer;
            }
            if payload.capacity > 0 {
                event.capacity = payload.capacity;
            }
            event.date_time = payload.date_time;
            storage.insert(id, event.clone());
            Ok(event)
        } else {
            Err(Message::NotFound("Event not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_event(id: u64, user_id: u64) -> Result<Message, Message> {
    authenticate_user(user_id)?;

    EVENTS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Event deleted.".to_string()))
        } else {
            Err(Message::NotFound("Event not found".to_string()))
        }
    })
}

#[ic_cdk::query]
fn get_events() -> Result<Vec<Event>, Message> {
    EVENTS_STORAGE.with(|storage| {
        let events: Vec<Event> = storage
            .borrow()
            .iter()
            .map(|(_, event)| event.clone())
            .collect();

        if events.is_empty() {
            Err(Message::NotFound("No events found".to_string()))
        } else {
            Ok(events)
        }
    })
}

#[ic_cdk::query]
fn get_event_by_id(id: u64) -> Result<Event, Message> {
    EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, event)| event.id == id)
            .map(|(_, event)| event.clone())
            .ok_or(Message::NotFound("Event not found".to_string()))
    })
}

#[ic_cdk::update]
fn rsvp_event(payload: RsvpEventPayload) -> Result<Message, Message> {
    if payload.alumni_id == 0 || payload.event_id == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'event_id' are provided.".to_string(),
        ));
    }

    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    let event = EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.event_id)
            .map(|event| event.clone())
    });
    if event.is_none() {
        return Err(Message::NotFound("Event not found".to_string()));
    }

    let mut event = event.unwrap();
    if event.attendees.len() as u32 >= event.capacity {
        return Err(Message::Error("Event is full.".to_string()));
    }

    if event.attendees.contains(&payload.alumni_id.to_string()) {
        return Err(Message::Error(
            "Alumni has already RSVP'd to the event.".to_string(),
        ));
    }

    event.attendees.push(payload.alumni_id.to_string());
    EVENTS_STORAGE.with(|storage| storage.borrow_mut().insert(payload.event_id, event));

    Ok(Message::Success("RSVP successful.".to_string()))
}

#[ic_cdk::update]
fn join_association(payload: JoinAssociationPayload) -> Result<Message, Message> {
    if payload.alumni_id == 0 || payload.association_id == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'association_id' are provided.".to_string(),
        ));
    }

    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.association_id)
            .map(|assoc| assoc.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    let mut association = association.unwrap();
    if association.alumnis.contains(&payload.alumni_id) {
        return Err(Message::Error(
            "Alumni is already a member of the association.".to_string(),
        ));
    }

    association.alumnis.push(payload.alumni_id);
    ASSOCIATIONS_STORAGE.with(|storage| storage.borrow_mut().insert(payload.association_id, association));

    Ok(Message::Success("Alumni joined the association.".to_string()))
}

#[ic_cdk::update]
fn leave_association(payload: LeaveAssociationPayload) -> Result<Message, Message> {
    if payload.alumni_id == 0 || payload.association_id == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'association_id' are provided.".to_string(),
        ));
    }

    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.association_id)
            .map(|assoc| assoc.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    let mut association = association.unwrap();
    association.alumnis.retain(|&id| id != payload.alumni_id);
    ASSOCIATIONS_STORAGE.with(|storage| storage.borrow_mut().insert(payload.association_id, association));

    Ok(Message::Success("Alumni left the association.".to_string()))
}

#[ic_cdk::update]
fn send_message_to_association(payload: MessagePayload) -> Result<Message, Message> {
    if payload.content.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'content' is provided.".to_string(),
        ));
    }

    let sender = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.sender_id)
            .map(|alumni| alumni.clone())
    });
    if sender.is_none() {
        return Err(Message::NotFound("Sender not found".to_string()));
    }

    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.association_id)
            .map(|assoc| assoc.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    let id = increment_id_counter()?;

    let message = MessageToAssociation {
        id,
        association_id: payload.association_id,
        sender_id: payload.sender_id,
        content: payload.content,
        created_at: current_time(),
    };
    MESSAGES_STORAGE.with(|storage| storage.borrow_mut().insert(id, message.clone()));
    Ok(Message::Success(
        "Message sent to association members.".to_string(),
    ))
}

#[ic_cdk::query]
fn search_alumni(payload: SearchAlumniPayload) -> Result<Vec<Alumni>, Message> {
    if payload.name.is_none() && payload.graduation_year.is_none() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' or 'graduation_year' is provided.".to_string(),
        ));
    }

    ALUMNI_STORAGE.with(|storage| {
        let alumni: Vec<Alumni> = storage
            .borrow()
            .iter()
            .filter(|(_, alumni)| {
                if let Some(name) = &payload.name {
                    if !alumni.name.contains(name) {
                        return false;
                    }
                }
                if let Some(graduation_year) = payload.graduation_year {
                    if alumni.graduation_year != graduation_year {
                        return false;
                    }
                }
                true
            })
            .map(|(_, alumni)| alumni.clone())
            .collect();

        if alumni.is_empty() {
            Err(Message::NotFound("No alumni found".to_string()))
        } else {
            Ok(alumni)
        }
    })
}

#[ic_cdk::update]
fn request_mentorship(payload: MentorshipRequestPayload) -> Result<MentorshipRequest, Message> {
    let requester = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.requester_id)
            .map(|alumni| alumni.clone())
    });
    if requester.is_none() {
        return Err(Message::NotFound("Requester not found".to_string()));
    }

    let mentor = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .get(&payload.mentor_id)
            .map(|alumni| alumni.clone())
    });
    if mentor.is_none() {
        return Err(Message::NotFound("Mentor not found".to_string()));
    }

    if payload.requester_id == payload.mentor_id {
        return Err(Message::Error("You cannot mentor yourself.".to_string()));
    }

    let id = increment_id_counter()?;

    let mentorship_request = MentorshipRequest {
        id,
        requester_id: payload.requester_id,
        mentor_id: payload.mentor_id,
        status: "pending".to_string(),
        created_at: current_time(),
    };
    MENTORSHIP_REQUESTS_STORAGE
        .with(|storage| storage.borrow_mut().insert(id, mentorship_request.clone()));
    Ok(mentorship_request)
}

#[ic_cdk::update]
fn approve_mentorship_request(request_id: u64, mentor_id: u64) -> Result<Message, Message> {
    MENTORSHIP_REQUESTS_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut request) = storage.get(&request_id) {
            if request.mentor_id != mentor_id {
                return Err(Message::UnAuthorized(
                    "Only the assigned mentor can approve the request.".to_string(),
                ));
            }
            request.status = "approved".to_string();
            storage.insert(request_id, request);
            Ok(Message::Success("Mentorship request approved.".to_string()))
        } else {
            Err(Message::NotFound(
                "Mentorship request not found".to_string(),
            ))
        }
    })
}

#[ic_cdk::update]
fn update_alumni(id: u64, payload: AlumniPayload, user_id: u64) -> Result<Alumni, Message> {
    authenticate_user(user_id)?;

    ALUMNI_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if let Some(mut alumni) = storage.get(&id) {
            if !payload.name.is_empty() {
                alumni.name = payload.name;
            }
            if !payload.email.is_empty() {
                alumni.email = payload.email;
            }
            alumni.graduation_year = payload.graduation_year;
            storage.insert(id, alumni.clone());
            Ok(alumni)
        } else {
            Err(Message::NotFound("Alumni not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_alumni(id: u64, user_id: u64) -> Result<Message, Message> {
    authenticate_user(user_id)?;

    ALUMNI_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Alumni deleted.".to_string()))
        } else {
            Err(Message::NotFound("Alumni not found".to_string()))
        }
    })
}

fn current_time() -> u64 {
    time()
}

fn authenticate_user(user_id: u64) -> Result<(), Message> {
    // Simple authentication check (this could be expanded to a real authentication system)
    if user_id == 0 {
        return Err(Message::UnAuthorized("Unauthorized user".to_string()));
    }
    Ok(())
}

fn increment_id_counter() -> Result<u64, Message> {
    ID_COUNTER.with(|counter| {
        let mut counter = counter.borrow_mut();
        let current_value = *counter.get();
        if current_value == u64::MAX {
            return Err(Message::Error("ID counter overflow".to_string()));
        }
        counter.set(current_value + 1).map_err(|e| {
            Message::Error(format!("Failed to increment counter: {:?}", e))
        })?;
        Ok(current_value + 1)
    })
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
}

ic_cdk::export_candid!();