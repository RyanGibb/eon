@0xdcaa43aa8c57d4a8;

interface Pipe {
  read @0 () -> (data :Data);
  write @1 (data :Data) -> ();
}
