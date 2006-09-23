package org.apache.commons.ssl;

import org.apache.log4j.Logger;

/**
 * <p>
 * Wraps a Log4j Logger.  This non-public class is the one actually interacting
 * with the log4j.jar library.  That way LogWrapper can safely attempt to use
 * log4j.jar, but still degrade gracefully and provide logging via standard-out
 * even if log4j is unavailable.
 * <p>
 * The interactions with log4j.jar could be done directly inside LogWrapper
 * as long as the Java code is compiled by Java 1.4 or greater (still works
 * at runtime in Java 1.3).  The interactions with log4j.jar only need to be
 * pushed out into a separate class like this for people using a Java 1.3
 * compiler, which creates bytecode that is more strict with depedency
 * checking.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 3-Aug-2006
 */
final class LogHelper
{
  private final Logger l;
  LogHelper( Class c )              { l = Logger.getLogger( c ); }
  LogHelper( String s )             { l = Logger.getLogger( s ); }
  void debug(Object o)              { l.debug(o);                }
  void debug(Object o, Throwable t) { l.debug(o,t);              }
  void info (Object o)              { l.info(o);                 }
  void info (Object o, Throwable t) { l.info(o,t);               }
  void warn (Object o)              { l.warn(o);                 }
  void warn (Object o, Throwable t) { l.warn(o,t);               }
  void error(Object o)              { l.error(o);                }
  void error(Object o, Throwable t) { l.error(o,t);              }
  void fatal(Object o)              { l.fatal(o);                }
  void fatal(Object o, Throwable t) { l.fatal(o,t);              }
  boolean isDebugEnabled()          { return l.isDebugEnabled(); }
  boolean isInfoEnabled()           { return l.isInfoEnabled();  }
  Object getLog4jLogger()           { return l;                  }
}
