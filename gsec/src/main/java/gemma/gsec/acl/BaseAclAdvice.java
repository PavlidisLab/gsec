/*
 * The gemma-core project
 *
 * Copyright (c) 2013 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package gemma.gsec.acl;

import gemma.gsec.AuthorityConstants;
import gemma.gsec.acl.domain.AclGrantedAuthoritySid;
import gemma.gsec.acl.domain.AclPrincipalSid;
import gemma.gsec.acl.domain.AclService;
import gemma.gsec.model.Securable;
import gemma.gsec.model.SecuredChild;
import gemma.gsec.model.SecuredNotChild;
import gemma.gsec.util.SecurityUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.hibernate.Hibernate;
import org.hibernate.LazyInitializationException;
import org.hibernate.SessionFactory;
import org.hibernate.engine.spi.CascadeStyle;
import org.hibernate.engine.spi.CascadingAction;
import org.hibernate.persister.entity.EntityPersister;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeanUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;

/**
 * Adds security controls to newly created objects (including those created by updates to other objects via cascades),
 * and removes them for objects that are deleted. Methods in this interceptor are run for all new objects (to add
 * security if needed) and when objects are deleted. This is not used to modify permissions on existing objects.
 * <p>
 * This is designed to be reusable, but it's not trivial; it requires substantial care from the implementer who override
 * the protected methods. Looking at the AclAdvice in Gemma can give some ideas of what kinds of things have to be
 * handled.
 *
 * @author keshav
 * @author pavlidis
 * @version $Id: BaseAclAdvice.java,v 1.1 2013/09/14 16:56:03 paul Exp $
 */
@SuppressWarnings("unused")
public abstract class BaseAclAdvice {

    private static final Log log = LogFactory.getLog( BaseAclAdvice.class );

    private final AclService aclService;
    private final SessionFactory sessionFactory;
    private final ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy;

    protected BaseAclAdvice( AclService aclService, SessionFactory sessionFactory, ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy ) {
        this.aclService = aclService;
        this.sessionFactory = sessionFactory;
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    public final void doAclAdvice( JoinPoint jp, Object retValue ) {
        //

        final Object[] args = jp.getArgs();
        Signature signature = jp.getSignature();
        final String methodName = signature.getName();

        // Class<?>[] clazzes = new Class[jp.getArgs().length];
        // for ( int i = 0; i < jp.getArgs().length; i++ ) {
        // clazzes[i] = jp.getArgs().getClass();
        // }
        // Method m = signature.getDeclaringType().getDeclaredMethod( signature.getName(), clazzes );
        // Transactional annotation = m.getAnnotation( Transactional.class );
        // if ( annotation != null && !annotation.readOnly() ) {
        // return;
        // }

        assert args != null;
        final Object persistentObject = getPersistentObject( retValue, methodName, args );

        if ( persistentObject == null ) return;

        final boolean isUpdate = methodIsUpdate( methodName );
        final boolean isDelete = methodIsDelete( methodName );

        // Case 1: collection of securables.
        if ( Collection.class.isAssignableFrom( persistentObject.getClass() ) ) {
            for ( final Object o : ( Collection<?> ) persistentObject ) {
                if ( isIneligibleForAcl( o ) ) {
                    continue; // possibly could return, if we assume collection is homogeneous in type.
                }
                process( o, methodName, isUpdate, isDelete );
            }
        } else {
            // Case 2: single securable
            if ( isIneligibleForAcl( persistentObject ) ) {
                /*
                 * This fails for methods that delete entities given an id.
                 */
                return;
            }
            process( persistentObject, methodName, isUpdate, isDelete );
        }

    }

    // from gemma reflectionutil
    @Nullable
    private Object getProperty( Object object, PropertyDescriptor descriptor ) throws IllegalAccessException,
        InvocationTargetException {
        Method getter = descriptor.getReadMethod();
        return getter.invoke( object );
    }

    /**
     * Check for special cases of objects that don't need to be examined for associations at all, for efficiency when
     * following associations. Default implementation always returns false.
     */
    protected boolean canSkipAclCheck( Object object ) {
        return false;
    }

    /**
     * Check if the association may be skipped. Default implementation always returns false.
     *
     * @param object       the target object which has the property
     * @param propertyName the name of the property to consider skipping
     */
    protected boolean canSkipAssociationCheck( Object object, String propertyName ) {
        return false;
    }

    /**
     * Subclasses can modify this to address special cases. Default implementation is a no-op.
     * <p>
     * FIXME this might not be necessary.
     *
     * @param acl       may be modified by this call
     * @param parentAcl value may be changed by this call
     * @param sid       value may be changed by this call
     */
    protected void createOrUpdateAclSpecialCases( MutableAcl acl, @Nullable Acl parentAcl, Sid sid, Securable object ) {
    }

    protected boolean currentUserIsAdmin() {
        return SecurityUtil.isUserAdmin();
    }

    protected boolean currentUserIsAnonymous() {
        return SecurityUtil.isUserAnonymous();
    }

    protected boolean currentUserIsRunningAsAdmin() {
        return SecurityUtil.isRunningAsAdmin();
    }

    /**
     * For use by other overridden methods.
     */
    protected final AclService getAclService() {
        return aclService;
    }

    protected abstract GrantedAuthority getUserGroupGrantedAuthority( Securable object );

    protected abstract String getUserName( Securable object );

    /**
     * Called during create. Default implementation returns null unless the object is a SecuredChild, in which case it
     * returns the value of s.getSecurityOwner() (which will be null unless it is filled in)
     * <p>
     * For some cases, we want to find the parent so we don't have to rely on updates later to catch it and fill it in.
     * Implementers must decide which cases can be handled this way. Care is required: the parent might not be created
     * yet, in which case the cascade to s is surely going to fix it later. The best situation is when s has an accessor
     * to reach the parent.
     *
     * @param s which might have a parent already in the system
     */
    protected Acl locateParentAcl( SecuredChild s ) {
        Securable parent = locateSecuredParent( s );

        if ( parent != null ) return this.getAclService().readAclById( makeObjectIdentity( parent ) );

        return null;
    }

    /**
     * Forms the object identity to be inserted in acl_object_identity table. Note that this does not add an
     * ObjectIdentity to the database; it just calls 'new'.
     *
     * @param object A persistent object
     * @return object identity.
     */
    protected final ObjectIdentity makeObjectIdentity( Securable object ) {
        return objectIdentityRetrievalStrategy.getObjectIdentity( object );
    }

    protected abstract boolean objectIsUser( Securable object );

    protected abstract boolean objectIsUserGroup( Securable object );

    /**
     * Called when objects are first created in the system and need their permissions initialized. Insert the access
     * control entries that all objects should have (unless they inherit from another object).
     * <p>
     * Default implementation does the following:
     * <ul>
     * <li>All objects are administratable by GROUP_ADMIN
     * <li>GROUP_AGENT has READ permissions on all objects
     * <li>If the current user is an adminisrator, and keepPrivateEvenWhenAdmin is false, the object gets READ
     * permissions for ANONYMOUS.
     * <li>If the current user is a "regular user" (non-admin) give them read/write permissions.
     */
    protected void setupBaseAces( MutableAcl acl, ObjectIdentity oi, Sid sid, boolean keepPrivateEvenWhenAdmin ) {

        /*
         * All objects must have administration permissions on them.
         */
        if ( log.isDebugEnabled() ) log.debug( "Making administratable by GROUP_ADMIN: " + oi );
        grant( acl, BasePermission.ADMINISTRATION, new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
            AuthorityConstants.ADMIN_GROUP_AUTHORITY ) ) );

        /*
         * Let agent read anything
         */
        if ( log.isDebugEnabled() ) log.debug( "Making readable by GROUP_AGENT: " + oi );
        grant( acl, BasePermission.READ, new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
            AuthorityConstants.AGENT_GROUP_AUTHORITY ) ) );

        /*
         * If admin, and the object is not a user or group, make it readable by anonymous.
         */
        boolean makeAnonymousReadable = this.currentUserIsAdmin() && !keepPrivateEvenWhenAdmin;

        if ( makeAnonymousReadable ) {
            if ( log.isDebugEnabled() ) log.debug( "Making readable by IS_AUTHENTICATED_ANONYMOUSLY: " + oi );
            grant( acl, BasePermission.READ, new AclGrantedAuthoritySid( new SimpleGrantedAuthority(
                AuthenticatedVoter.IS_AUTHENTICATED_ANONYMOUSLY ) ) );
        }

        /*
         * Don't add more permissions for the administrator. But whatever it is, the person who created it can
         * read/write it. User will only be anonymous if they are registering (AFAIK)
         */
        if ( !this.currentUserIsAdmin() && !this.currentUserIsAnonymous() ) {

            if ( log.isDebugEnabled() ) log.debug( "Giving read/write permissions on " + oi + " to " + sid );
            grant( acl, BasePermission.READ, sid );

            /*
             * User who created something can edit it.
             */
            grant( acl, BasePermission.WRITE, sid );

        }

    }

    /**
     * For cases where don't have a cascade but the other end is securable, so we <em>must</em> check the association.
     * For example, when we persist an EE we also persist any new ADs in the same transaction. Thus the ADs need ACL
     * attention at the same time (via the BioAssays).
     *
     * @param object   we are checking
     * @param property of the object
     * @return true if the association should be followed (even though it might not be based on cascade status)
     */
    protected boolean specialCaseForAssociationFollow( Object object, String property ) {
        return false;

    }

    /**
     * For cases in which the object is not a SecuredChild, but we still want to erase ACEs on it when it has a parent.
     * Implementers will check the class of the object, and the class of the parent (e.g. using <code>Class.forName(
     * parentAcl.getObjectIdentity().getType() )</code>) and decide what to do.
     *
     * @return false if ACEs should be retained. True if ACEs should be removed (if possible).
     */
    protected boolean specialCaseToAllowRemovingAcesFromChild( Securable object, Acl parentAcl ) {
        return false;
    }

    /**
     * Indicate if the given object should not be made public immediately on creation by administrators.
     * <p>
     * The default implementation returns true if the object is a {@link SecuredChild}; otherwise false.
     *
     * @return true if it's a special case to be kept private on creation.
     */
    protected boolean specialCaseToKeepPrivateOnCreation( Securable object ) {
        return object instanceof SecuredChild;
    }

    /**
     * Creates the Acl object.
     *
     * @param acl       If non-null we're in update mode, possibly setting the parent.
     * @param object    The domain object.
     * @param parentAcl can be null
     */
    private void addOrUpdateAcl( @Nullable MutableAcl acl, Securable object, @Nullable Acl parentAcl ) {

        if ( object.getId() == null ) {
            log.warn( "ACLs cannot be added or updated on non-persistent object: " + object );
            return;
        }

        if ( log.isTraceEnabled() ) log.trace( "Checking for ACLS on " + object );
        ObjectIdentity oi = makeObjectIdentity( object );

        boolean create = false;
        if ( acl == null ) {
            // usually create, but could be update.
            try {
                // this is probably redundant. We shouldn't have ACLs already.
                acl = ( MutableAcl ) getAclService().readAclById( oi ); // throws exception if not found
                /*
                 * If we get here, we're in update mode after all. Could be findOrCreate, or could be a second pass that
                 * will let us fill in parent ACLs for associated objects missed earlier in a persist cycle. E.g.
                 * BioMaterial
                 */
                try {
                    maybeSetParentACL( object, acl, parentAcl );
                    return;
                } catch ( NotFoundException nfe ) {
                    log.error( nfe, nfe );
                }
            } catch ( NotFoundException nfe ) {
                // the current user will be the owner.
                acl = getAclService().createAcl( oi );
                create = true;
                assert acl != null;
                assert acl.getOwner() != null;
            }
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if ( authentication == null ) {
            throw new IllegalStateException( "No authentication found in the security context" );
        }

        Object p = authentication.getPrincipal();

        if ( p == null ) {
            throw new IllegalStateException( "Principal was null for " + authentication );
        }

        AclPrincipalSid sid = new AclPrincipalSid( p.toString() );

        boolean isAdmin = currentUserIsAdmin();

        boolean isRunningAsAdmin = currentUserIsRunningAsAdmin();

        boolean objectIsAUser = objectIsUser( object );

        boolean objectIsAGroup = objectIsUserGroup( object );

        boolean keepPrivateEvenWhenAdmin = this.specialCaseToKeepPrivateOnCreation( object );

        /*
         * The only case where we absolutely disallow inheritance is for SecuredNotChild.
         */
        boolean inheritFromParent = parentAcl != null && !( object instanceof SecuredNotChild );

        boolean missingParent = parentAcl == null && object instanceof SecuredChild;

        if ( missingParent ) {
            // This easily happens, it's not a problem as we go back through to recheck objects. Example: analysis,
            // before associated with experiment.
            if ( log.isDebugEnabled() ) log.debug( "Object did not have a parent during ACL setup: " + object );
        }

        /*
         * The logic here is: if we're supposed to inherit from the parent, but none is provided (can easily happen), we
         * have to put in ACEs. Same goes if we're not supposed to inherit. Objects which are not supposed to have their
         * own ACLs (SecurableChild)
         */
        if ( create && !inheritFromParent ) {
            setupBaseAces( acl, oi, sid, keepPrivateEvenWhenAdmin );

            /*
             * Make sure user groups can be read by future members of the group
             */
            if ( objectIsAGroup ) {
                GrantedAuthority ga = getUserGroupGrantedAuthority( object );
                if ( log.isDebugEnabled() ) log.debug( "Making group readable by " + ga + ": " + oi );
                grant( acl, BasePermission.READ, new AclGrantedAuthoritySid( ga ) );
            }

        } else {
            assert !acl.getEntries().isEmpty()
                || ( parentAcl != null && !parentAcl.getEntries().isEmpty() ) : "Failed to get valid ace for acl or parents: "
                + acl + " parent=" + parentAcl;
        }

        /*
         * If the object is a user, make sure that user gets permissions even if the current user is not the same! In
         * fact, user creation runs with RUN_AS_ADMIN privileges.
         */

        if ( create && objectIsAUser ) {
            String userName = getUserName( object );
            if ( sid.getPrincipal().equals( userName ) ) {
                /*
                 * This case should actually never happen. "we" are the user who is creating this user. We've already
                 * adding the READ/WRITE permissions above.
                 */
                log.warn( "Somehow...a user created themselves: " + oi );

            } else {

                if ( log.isDebugEnabled() )
                    log.debug( "New User: given read/write permissions on " + oi + " to " + sid );

                if ( isRunningAsAdmin ) {
                    /*
                     * Important: we expect this to normally be the case, that users are added while running in
                     * temporarily elevated status.
                     */
                    sid = new AclPrincipalSid( userName );
                    acl.setOwner( sid );
                }

                /*
                 * See org.springframework.security.acls.domain.AclAuthorizationStrategy.
                 */
                grant( acl, BasePermission.READ, sid );
                grant( acl, BasePermission.WRITE, sid );

            }
        }

        createOrUpdateAclSpecialCases( acl, parentAcl, sid, object );

        /*
         * Only the owner or an administrator can do these operations, and only in those cases would they be necessary
         * anyway (primarily in creating the objects in the first place, there's nearly no conceivable reason to change
         * these after creation.)
         */
        if ( sid.equals( acl.getOwner() ) || isAdmin ) {

            if ( isAdmin && acl.getOwner() == null ) {
                // don't change the owner.
                acl.setOwner( sid );
            }

            if ( parentAcl != null && inheritFromParent ) {
                if ( log.isTraceEnabled() )
                    log.trace( "Setting parent to: " + parentAcl.getObjectIdentity() + " <--- "
                        + acl.getObjectIdentity() );
                acl.setParent( parentAcl );
            }
            acl.setEntriesInheriting( inheritFromParent );
            this.maybeClearACEsOnChild( object, acl, parentAcl );
        }

        // finalize.
        getAclService().updateAcl( acl );

    }

    /**
     * Determine which ACL is going to be the parent of the associations of the given object.
     * <p>
     * If the object is a SecuredNotChild, then it will be treated as the parent. For example, ArrayDesigns associated
     * with an Experiment has 'parent status' for securables associated with the AD, such as LocalFiles.
     */
    @Nullable
    private Acl chooseParentForAssociations( Object object, @Nullable Acl previousParent ) {
        Acl parentAcl;
        if ( SecuredNotChild.class.isAssignableFrom( object.getClass() )
            || ( previousParent == null && Securable.class.isAssignableFrom( object.getClass() ) && !SecuredChild.class
            .isAssignableFrom( object.getClass() ) ) ) {

            parentAcl = getAcl( ( Securable ) object );
        } else {
            /*
             * Keep the previous parent. This means we 'pass through' and the parent is basically going to be the
             * top-most object: there isn't a hierarchy of parenthood. This also means that the parent might be kept as
             * null.
             */
            parentAcl = previousParent;

        }
        return parentAcl;
    }

    /**
     * Delete acl permissions for an object.
     */
    private void deleteAcl( Securable object ) throws DataAccessException, IllegalArgumentException {
        ObjectIdentity oi = makeObjectIdentity( object );

        if ( oi == null ) {
            log.warn( "Null object identity for : " + object );
        }

        if ( log.isDebugEnabled() ) {
            log.debug( "Deleting ACL for " + object );
        }

        /*
         * This deletes children with the second parameter = true.
         */
        this.getAclService().deleteAcl( oi, true );
    }

    @Nullable
    private MutableAcl getAcl( Securable s ) {
        ObjectIdentity oi = objectIdentityRetrievalStrategy.getObjectIdentity( s );

        try {
            return ( MutableAcl ) getAclService().readAclById( oi );
        } catch ( NotFoundException e ) {
            return null;
        }
    }

    @Nullable
    private Object getPersistentObject( Object retValue, String methodName, Object[] args ) {
        if ( methodIsDelete( methodName ) || methodIsUpdate( methodName ) ) {

            /*
             * Only deal with single-argument update methods. MIGHT WANT TO RETURN THE FIRST ARGUMENT
             */
            if ( args.length > 1 ) return null;

            assert args.length > 0;
            return args[0];
        }
        return retValue;
    }

    /**
     * Add ACE granting permission to sid to ACL (does not persist the change, you have to call update!)
     *
     * @param acl        which object
     * @param permission which permission
     * @param sid        which principal
     */
    private void grant( MutableAcl acl, Permission permission, Sid sid ) {
        acl.insertAce( acl.getEntries().size(), permission, sid, true );
    }

    private boolean isIneligibleForAcl( Object c ) {
        return !( c instanceof Securable );
    }

    /**
     * Recursively locate the actual secured parent.
     */
    @Nullable
    private Securable locateSecuredParent( SecuredChild s ) {
        if ( s.getSecurityOwner() == null ) {
            return null;

        }
        Securable securityOwner = s.getSecurityOwner();

        if ( securityOwner instanceof SecuredChild ) {
            return locateSecuredParent( ( SecuredChild ) securityOwner );
        }
        return securityOwner;

    }

    /**
     * When setting the parent, we check to see if we can delete the ACEs on the 'child', if any. This is because we
     * want permissions to be managed by the parent, so ACEs on the child are redundant and possibly a source of later
     * trouble. Special cases are handled by specialCaseToAllowRemovingAcesFromChild.
     * <p>
     * Before deleting anything, we check that the ACEs on the child are exactly equivalent to the ones on the parent.
     * If they aren't, it implies the child was not correctly synchronized with the parent in the first place.
     *
     * @param parentAcl -- careful with the order!
     * @throws IllegalStateException if the parent has no ACEs.
     */
    private boolean maybeClearACEsOnChild( Securable object, MutableAcl childAcl, @Nullable Acl parentAcl ) {
        if ( parentAcl == null ) return false;
        if ( object instanceof SecuredNotChild ) return false;

        int aceCount = childAcl.getEntries().size();

        if ( aceCount == 0 ) {
            if ( parentAcl.getEntries().size() == 0 ) {
                throw new IllegalStateException( "Either the child or the parent has to have ACEs" );
            }
            return false;
        }

        boolean force = specialCaseToAllowRemovingAcesFromChild( object, parentAcl );

        if ( parentAcl.getEntries().size() == aceCount || force ) {

            boolean oktoClearACEs = true;

            // check for exact match of all ACEs
            for ( AccessControlEntry ace : parentAcl.getEntries() ) {
                boolean found = false;
                for ( AccessControlEntry childAce : childAcl.getEntries() ) {
                    if ( childAce.getPermission().equals( ace.getPermission() )
                        && childAce.getSid().equals( ace.getSid() ) ) {
                        found = true;
                        log.trace( "Removing ace from child: " + ace );
                        break;
                    }
                }

                if ( !found ) {
                    log.warn( "Didn't find matching permission for " + ace + " from parent "
                        + parentAcl.getObjectIdentity() );
                    log.warn( "Parent acl: " + parentAcl );
                    oktoClearACEs = false;
                    break;
                }
            }

            if ( force || oktoClearACEs ) {
                assert childAcl.getParentAcl() != null : "Child lacks parent " + childAcl + " force=" + force;

                if ( log.isTraceEnabled() ) log.trace( "Erasing ACEs from child " + object );

                while ( childAcl.getEntries().size() > 0 ) {
                    childAcl.deleteAce( 0 );
                }

                return true;
            }

        } else {
            /*
             * This should often be an error condition. The child should typically have the same permissions as the
             * parent, if they are out of synch that's a special situation.
             *
             * For example: a differential expression analysis should not be public when the experiment is private. That
             * won't work!
             */
            log.warn( "Could not clear aces on child" );
            log.warn( "Parent: " + parentAcl );
            log.warn( "Child: " + childAcl );
            // throw new IllegalStateException( "Could not clear aces on child: " + childAcl.getObjectIdentity() );

        }

        return false;
    }

    /**
     * This is used when rechecking objects that are detached from a parent. Typically these are {@link SecuredChild}ren
     * like BioAssays.
     * <p>
     * Be careful with the argument order!
     *
     * @param childAcl  - the potential child
     * @param parentAcl - the potential parent
     */
    private void maybeSetParentACL( final Securable object, MutableAcl childAcl, @Nullable final Acl parentAcl ) {
        if ( parentAcl != null && !SecuredNotChild.class.isAssignableFrom( object.getClass() ) ) {

            Acl currentParentAcl = childAcl.getParentAcl();

            if ( currentParentAcl != null && !currentParentAcl.equals( parentAcl ) ) {
                throw new IllegalStateException( "Cannot change parentAcl on " + object
                    + " once it has ben set:\n Current parent: " + currentParentAcl + " != \nProposed parent:"
                    + parentAcl );
            }

            boolean changedParentAcl = false;
            if ( currentParentAcl == null ) {
                log.trace( "Setting parent ACL to child=" + childAcl + " parent=" + parentAcl );
                childAcl.setParent( parentAcl );
                childAcl.setEntriesInheriting( true );
                changedParentAcl = true;
            }

            boolean clearedACEs = maybeClearACEsOnChild( object, childAcl, parentAcl );

            if ( changedParentAcl || clearedACEs ) {
                getAclService().updateAcl( childAcl );
            }
        }
        childAcl.getParentAcl();
    }

    /**
     * Do necessary ACL operations on the object.
     */
    private void process( final Object o, final String methodName, final boolean isUpdate, final boolean isDelete ) {

        Securable s = ( Securable ) o;

        assert s != null;

        if ( isUpdate ) {
            if ( log.isTraceEnabled() ) log.trace( "***********  Start update ACL on " + o + " *************" );
            startUpdate( methodName, s );
        } else if ( isDelete ) {
            if ( log.isTraceEnabled() ) log.trace( "***********  Start delete ACL on " + o + " *************" );
            deleteAcl( s );
        } else {
            if ( log.isTraceEnabled() ) log.trace( "***********  Start create ACL on " + o + " *************" );
            startCreate( methodName, s );
        }

        if ( log.isTraceEnabled() ) log.trace( "*========* End ACL on " + o + " *=========*" );
    }

    /**
     * Walk the tree of associations and add (or update) acls.
     *
     * @param methodName     method name
     * @param previousParent The parent ACL of the given object (if it is a Securable) or of the last visited Securable.
     */
    @SuppressWarnings("unchecked")
    private void processAssociations( String methodName, Object object, @Nullable Acl previousParent ) {

        if ( canSkipAclCheck( object ) ) {
            return;
        }

        EntityPersister persister = ( EntityPersister ) sessionFactory.getClassMetadata( Hibernate.getClass( object ) );
        if ( persister == null ) {
            log.error( "No Entity Persister found for " + object.getClass().getName() );
            return;
        }
        CascadeStyle[] cascadeStyles = persister.getPropertyCascadeStyles();
        String[] propertyNames = persister.getPropertyNames();

        Acl parentAcl = chooseParentForAssociations( object, previousParent );

        for ( int j = 0; j < propertyNames.length; j++ ) {

            CascadeStyle cs = cascadeStyles[j];
            String propertyName = propertyNames[j];

            // log.warn( propertyName );

            /*
             * The goal here is to avoid following associations that don't need to be checked. Unfortunately, this can
             * be a bit tricky because there are exceptions. This is kind of inelegant, but the alternative is to check
             * _every_ association, which will often not be reachable.
             */
            if ( !specialCaseForAssociationFollow( object, propertyName )
                && ( canSkipAssociationCheck( object, propertyName ) || !needCascade( methodName, cs ) ) ) {
                // if ( log.isTraceEnabled() )
                // log.trace( "Skipping checking association: " + propertyName + " on " + object );
                continue;
            }

            PropertyDescriptor descriptor = BeanUtils.getPropertyDescriptor( object.getClass(), propertyName );

            Object associatedObject;
            try {
                // FieldUtils DOES NOT WORK correctly with proxies
                associatedObject = getProperty( object, descriptor );
            } catch ( LazyInitializationException e ) {
                /*
                 * This is not a problem. If this was reached via a create, the associated objects must not be new so
                 * they should already have acls.
                 */

                /*
                 * Well, that's the dream. We don't want warnings every time, that's for sure.
                 */
                if ( log.isTraceEnabled() )
                    log.trace( "Association was unreachable during ACL association checking: " + propertyName + " on "
                        + object );
                return;
            } catch ( Exception e ) {
                throw new RuntimeException( "Failure during association check of: " + propertyName + " on " + object, e );
            }

            if ( associatedObject == null ) continue;

            if ( associatedObject instanceof Collection ) {
                Collection<Object> associatedObjects = ( Collection<Object> ) associatedObject;

                try {
                    for ( Object object2 : associatedObjects ) {

                        if ( Securable.class.isAssignableFrom( object2.getClass() ) ) {
                            addOrUpdateAcl( null, ( Securable ) object2, parentAcl );
                        } else if ( log.isTraceEnabled() ) {
                            log.trace( object2 + ": not securable, skipping" );
                        }
                        processAssociations( methodName, object2, parentAcl );
                    }
                } catch ( LazyInitializationException ok ) {
                    /*
                     * This is not a problem. If this was reached via a create, the associated objects must not be new
                     * so they should already have acls.
                     */

                    /*
                     * Well, that's the dream. We don't want warnings every time, that's for sure.
                     */
                    if ( log.isTraceEnabled() )
                        log.trace( "Association was unreachable during ACL association checking: " + propertyName
                            + " on " + object );
                }

            } else {
                Class<?> propertyType = descriptor.getPropertyType();
                if ( Securable.class.isAssignableFrom( propertyType ) ) {
                    addOrUpdateAcl( null, ( Securable ) associatedObject, parentAcl );
                }
                processAssociations( methodName, associatedObject, parentAcl );
            }
        }
    }

    private void startCreate( String methodName, Securable s ) {

        /*
         * Note that if the method is findOrCreate, we'll return quickly.
         */

        ObjectIdentity oi = makeObjectIdentity( s );

        if ( oi == null ) {
            throw new IllegalStateException(
                "On 'create' methods, object should have a valid objectIdentity available. Method=" + methodName
                    + " on " + s );
        }

        Acl parentAcl = SecuredChild.class.isAssignableFrom( s.getClass() ) ? locateParentAcl( ( SecuredChild ) s )
            : null;

        addOrUpdateAcl( null, s, parentAcl );
        processAssociations( methodName, s, null );

    }

    /**
     * Kick off an update. This is executed when we call fooService.update(s). The basic issue is to add permissions for
     * any <em>new</em> associated objects.
     *
     * @param m the update method
     * @param s the securable being updated.
     */
    private void startUpdate( String m, Securable s ) {

        ObjectIdentity oi = makeObjectIdentity( s );

        // this is not persistent.
        assert oi != null;
        MutableAcl acl = null;
        Acl parentAcl = null;
        try {
            acl = ( MutableAcl ) getAclService().readAclById( oi );
            assert acl != null;
            parentAcl = acl.getParentAcl(); // can be null.
        } catch ( NotFoundException nfe ) {
            /*
             * This really should be an error.
             */

            /*
             * Then, this shouldn't be an update.
             */
            log.warn( "On 'update' methods, there should be a ACL on the passed object already. Method=" + m + " on "
                + s );
        }

        addOrUpdateAcl( acl, s, parentAcl );
        processAssociations( m, s, parentAcl );
    }


    private boolean methodIsDelete( String s ) {
        return s.equals( "remove" ) || s.equals( "delete" );
    }

    private boolean methodIsUpdate( String s ) {
        return s.equals( "update" ) || s.equals( "persistOrUpdate" );
    }

    private boolean needCascade( String m, CascadeStyle cs ) {
        if ( methodIsDelete( m ) ) {
            return cs.doCascade( CascadingAction.DELETE );
        }
        return cs.doCascade( CascadingAction.PERSIST ) || cs.doCascade( CascadingAction.SAVE_UPDATE );
    }
}