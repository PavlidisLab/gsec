/*
 * The Gemma project.
 * 
 * Copyright (c) 2006-2007 University of British Columbia
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
 */package gemma.gsec.mda;

import java.util.Collection;

/**
 * Interface that supports basic CRUD operations.
 * 
 * @author paul
 * @version $Id: BaseDao.java,v 1.8 2013/09/21 22:16:40 paul Exp $
 * @param <T>
 */
public interface BaseDao<T> {

    public Collection<? extends T> create( Collection<? extends T> entities );

    /**
     * Create an object. If the entity type is immutable, this may also delete any existing entities identified by an
     * appropriate 'find' method.
     * 
     * @param entity
     * @return
     */
    public T create( T entity );

    public Collection<? extends T> load( Collection<Long> ids );

    public T load( Long id );

    public Collection<? extends T> loadAll();

    public void remove( Collection<? extends T> entities );

    /**
     * Remove a persistent instance based on its id. The implementer is trusted to know what type of object to remove.
     * <p>
     * Note that this method is to be avoided for Securables, because it will leave cruft in the ACL tables. We may fix
     * this by having this method return the removed object.
     * 
     * @param id
     */
    public void remove( Long id );

    /**
     * Remove a persistent instance
     * 
     * @param entity
     */
    public void remove( T entity );

    /**
     * Update the entities. Not supported if the entities are immutable.
     * 
     * @param entities
     */
    public void update( Collection<? extends T> entities );

    /**
     * Update the entity. Not supported if the entity is immutable.
     * 
     * @param entities
     */
    public void update( T entity );

}