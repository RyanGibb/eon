@0xdcaa43aa8c57d4a8;

interface Connection {
  create @0 () -> (stream :Stream);
  interface Stream {
    read @0 () -> (data :Data);
    write @1 (data :Data) -> ();
    close @2 () -> ();
  }
}
