package gemma.gsec.acl;

import gemma.gsec.model.Securable;
import gemma.gsec.model.SecuredChild;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.Sid;

import javax.annotation.Nullable;

/**
 * Special case handler for {@link AclAdvice}.
 * @author poirigui
 */
@SuppressWarnings("unused")
public interface AclAdviceSpecialCaseHandler {

    /**
     * Indicate if an object should be ignored when propagating ACLs.
     * <p>
     * Check for special cases of objects that don't need to be examined for associations at all, for efficiency when
     * following associations.
     */
    default boolean ignore( Object object ) {
        return false;
    }

    /**
     * Indicate if a property can be ignored when propagating ACLs.
     * <p>
     * Check if the association may be skipped.
     *
     * @param object       the target object which has the property
     * @param propertyName the name of the property to consider skipping
     */
    default boolean ignoreProperty( Object object, String propertyName ) {
        return false;
    }

    /**
     * Indicate if cascading of ACLs should be forced on a given property.
     * <p>
     * For cases where don't have a cascade but the other end is securable, so we <em>must</em> check the association.
     * For example, when we persist an EE we also persist any new ADs in the same transaction. Thus, the ADs need ACL
     * attention at the same time (via the BioAssays).
     *
     * @param object   we are checking
     * @param property of the object
     * @return true if the association should be followed (even though it might not be based on cascade status)
     */
    default boolean forceCascadeOnProperty( Object object, String property ) {
        return false;
    }

    /**
     * Invoked after ACLs have been either created or updated .
     */
    default void afterAclCreateOrUpdate( MutableAcl acl, @Nullable Acl parentAcl, Sid sid, Securable object ) {

    }

    /**
     * Indicate if the object should remain private on creation.
     */
    default boolean keepPrivateOnCreation( Securable object ) {
        return object instanceof SecuredChild;
    }
}
