/*
 * The Gemma project
 *
 * Copyright (c) 2012 University of British Columbia
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
package gemma.gsec.acl.afterinvocation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;

import gemma.gsec.SecurityService;
import gemma.gsec.acl.ValueObjectAwareIdentityRetrievalStrategyImpl;
import gemma.gsec.model.SecureValueObject;
import gemma.gsec.util.SecurityUtil;

/**
 * Security check for reading value objects. Also overrides default behaviour by returning null, rather than throwing an
 * access denied exception.
 * <p>
 * As a side effect, it fills in security status information in the value objects to which permission was granted.
 *
 * @author paul
 * @version $Id: AclAfterValueObjectProvider.java,v 1.7 2013/09/14 16:56:03 paul Exp $
 * @see AclAfterFilterValueObjectCollectionProvider for the same thing but for collections.
 */
public class AclAfterValueObjectProvider extends
        org.springframework.security.acls.afterinvocation.AclEntryAfterInvocationProvider {

    private static final Log log = LogFactory.getLog( AclAfterValueObjectProvider.class );

    @Autowired
    private SecurityService securityService;

    public AclAfterValueObjectProvider( AclService aclService, List<Permission> requirePermission ) {
        super( aclService, "AFTER_ACL_VALUE_OBJECT_READ", requirePermission );
        this.setObjectIdentityRetrievalStrategy( new ValueObjectAwareIdentityRetrievalStrategyImpl() );

    }

    @Override
    public Object decide( Authentication authentication, Object object, Collection<ConfigAttribute> config,
            Object returnedObject ) throws AccessDeniedException {
        try {

            if ( returnedObject == null || !SecureValueObject.class.isAssignableFrom( returnedObject.getClass() ) ) {
                // nothing to do here.
                return returnedObject;
            }

            /*
             * Populate optional fields in the ValueObject. Problem: some of these hit the database. Make this optional.
             */
            SecureValueObject svo = ( SecureValueObject ) returnedObject;

            boolean hasPermission = securityService.hasPermissionVO( svo, requirePermission, authentication );

            if ( !hasPermission ) return null;

            if ( SecurityUtil.isUserLoggedIn() ) {
                Acl acl = securityService.getAcl( svo );
                svo.setIsPublic( !SecurityUtil.isPrivate( acl ) );
                svo.setIsShared( SecurityUtil.isShared( acl ) );
                svo.setUserOwned( securityService.isOwnedByCurrentUser( svo ) );

                if ( svo.getUserOwned() || SecurityUtil.isUserAdmin()
                        || requirePermission.contains( BasePermission.WRITE ) ) {
                    svo.setUserCanWrite( true );
                } else {
                    List<Permission> writePermissions = new ArrayList<>();
                    writePermissions.add( BasePermission.WRITE );
                    svo.setUserCanWrite( securityService.hasPermissionVO( svo, writePermissions, authentication ) );
                }
            }
            return svo;
        } catch ( AccessDeniedException e ) {
            log.warn( e.getMessage() + ": returning null" );
            return null;
        }
    }

}
