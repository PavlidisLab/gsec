package gemma.gsec.acl.domain;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.acls.domain.AuditLogger;
import org.springframework.security.acls.model.AccessControlEntry;

public class AuditLoggerImpl implements AuditLogger {

    private static final Log log = LogFactory.getLog( AuditLoggerImpl.class );

    @Override
    public void logIfNeeded( boolean granted, AccessControlEntry ace ) {
        log.info( String.format( "%s due to ACE: %s", granted ? "GRANTED" : "DENIED", ace ) );
    }
}
