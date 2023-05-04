package gemma.gsec.acl.afterinvocation;

import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;

import java.util.List;

public class AclEntryAfterInvocationProvider extends org.springframework.security.acls.afterinvocation.AclEntryAfterInvocationProvider {

    public AclEntryAfterInvocationProvider( AclService aclService, String processConfigAttribute, List<Permission> requirePermission ) {
        super( aclService, processConfigAttribute, requirePermission );
    }

    @Override
    protected boolean hasPermission( Authentication authentication, Object domainObject ) {
        return hasPermission( authentication, domainObject, requirePermission );
    }

    protected boolean hasPermission( Authentication authentication, Object domainObject, List<Permission> requiredPermissions ) {
        List<Sid> sids = sidRetrievalStrategy.getSids( authentication );
        ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity( domainObject );
        try {
            Acl acl = aclService.readAclById( objectIdentity, sids );
            return acl.isGranted( requiredPermissions, sids, false );
        } catch ( NotFoundException ignore ) {
            return false;
        }
    }
}
