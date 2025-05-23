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

import org.springframework.security.core.GrantedAuthority;

/**
 * Represents an {@link org.springframework.security.core.GrantedAuthority} conferred by a group membership.
 *
 * @author ptan
 * @version $Id$
 */
public interface GroupAuthority extends GrantedAuthority {

}
