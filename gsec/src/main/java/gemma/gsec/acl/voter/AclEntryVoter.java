package gemma.gsec.acl.voter;

import gemma.gsec.acl.ObjectTransientnessRetrievalStrategy;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import javax.annotation.Nullable;
import java.util.Collection;

/**
 * An extension of {@link org.springframework.security.acls.AclEntryVoter}.
 * <p>
 * This voter also supports granting access to transient objects if a {@link ObjectTransientnessRetrievalStrategy}
 * is set and this voter is explicitly set to grant access to transient objects with {@link #setGrantOnTransient}.
 * @author poirigui
 */
public class AclEntryVoter extends org.springframework.security.acls.AclEntryVoter {

    @Nullable
    private ObjectTransientnessRetrievalStrategy objectTransientnessRetrievalStrategy;
    private boolean grantOnTransient;

    public AclEntryVoter( AclService aclService, String processConfigAttribute, Permission[] requirePermission ) {
        super( aclService, processConfigAttribute, requirePermission );
    }

    @Override
    public int vote( Authentication authentication, MethodInvocation object, Collection<ConfigAttribute> attributes ) {
        if ( objectTransientnessRetrievalStrategy != null ) {
            for ( ConfigAttribute attribute : attributes ) {
                if ( !this.supports( attribute ) ) {
                    continue;
                }

                Object domainObject = getDomainObjectInstance( object );

                if ( domainObject == null ) {
                    break;
                }

                if ( objectTransientnessRetrievalStrategy.isObjectTransient( domainObject ) ) {
                    return grantOnTransient ? ACCESS_GRANTED : ACCESS_ABSTAIN;
                }
            }
        }
        return super.vote( authentication, object, attributes );
    }

    /**
     * Set the strategy to retrieve the transientness of an object.
     */
    public void setObjectTransientnessRetrievalStrategy( @Nullable ObjectTransientnessRetrievalStrategy objectTransientnessRetrievalStrategy ) {
        this.objectTransientnessRetrievalStrategy = objectTransientnessRetrievalStrategy;
    }

    /**
     * Set whether to grant access to transient objects or simply abstain.
     */
    public void setGrantOnTransient( boolean grantOnTransient ) {
        this.grantOnTransient = grantOnTransient;
    }
}
