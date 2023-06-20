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
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

import javax.annotation.Nullable;
import java.io.Serializable;
import java.util.List;

/**
 * @author Paul
 * @version $Id: AclDao.java,v 1.1 2013/09/14 16:55:19 paul Exp $
 */
public interface AclDao extends LookupStrategy {

    AclObjectIdentity createObjectIdentity( String type, Serializable identifier, Sid sid, boolean entriesInheriting );

    void delete( ObjectIdentity objectIdentity, boolean deleteChildren );

    void delete( Sid sid );

    @Nullable
    AclObjectIdentity find( ObjectIdentity oid );

    @Nullable
    AclSid find( Sid sid );

    List<ObjectIdentity> findChildren( ObjectIdentity parentIdentity );

    AclSid findOrCreate( Sid sid );

    void update( MutableAcl acl );

}
