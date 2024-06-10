@0x8c940eaf41b95341;

struct SavedDomain {
  name @0 :Text;
  primary @1 :Text;
}

struct SavedSecondary {
  name @0 :Text;
}

struct SavedService {
  union {
    domain @0 :SavedDomain;
    secondary @1 :SavedSecondary;
  }
}

