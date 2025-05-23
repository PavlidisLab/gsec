/*
 * The gemma-gsec project
 *
 * Copyright (c) 2014 University of British Columbia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package gemma.gsec.model;

import java.util.Collection;
import java.util.Date;

/**
 * TODO Document Me
 *
 * @author ptan
 * @version $Id$
 */
public interface User extends Securable, SecuredNotChild {

    boolean isEnabled();

    String getPassword();

    String getPasswordHint();

    String getSignupToken();

    Date getSignupTokenDatestamp();

    String getUserName();

    String getEmail();

    Collection<? extends UserGroup> getGroups();
}
