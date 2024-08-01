package com.sohoffice.security.authorization.io;

import java.util.List;

public interface AuthStatement {
  List<String> resources();

  List<String> principals();

  List<String> actions();

  AuthEffect effect();

  String identifier();
}
