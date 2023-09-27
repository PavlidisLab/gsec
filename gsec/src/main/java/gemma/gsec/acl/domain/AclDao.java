/*
 * The gemma-mda project
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
package gemma.gsec.acl.domain;

import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nullable;
import java.util.List;

/**
 * @author Paul
 * @version $Id: AclDao.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
public interface AclDao extends LookupStrategy {

    /**
     * Find an ACL object identity confirming to the given object identity.
     */
    @Nullable
    AclObjectIdentity findObjectIdentity( AclObjectIdentity objectIdentity );

    List<AclObjectIdentity> findChildren( AclObjectIdentity parentIdentity );

    /**
     * Create a new object identity.
     */
    @CheckReturnValue
    AclObjectIdentity createObjectIdentity( AclObjectIdentity oid );

    /**
     * Update a given object identity so that it conforms to a given ACL object.
     */
    void updateObjectIdentity( AclObjectIdentity aclObjectIdentity, Acl acl );

    void deleteObjectIdentity( AclObjectIdentity objectIdentity, boolean deleteChildren );

    void deleteSid( AclSid sid );

    @Nullable
    AclSid findSid( AclSid sid );

    @CheckReturnValue
    AclSid findOrCreateSid( AclSid sid );
}
