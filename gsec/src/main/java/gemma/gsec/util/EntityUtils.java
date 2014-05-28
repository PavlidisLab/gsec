/*
 * The Gemma project
 * 
 * Copyright (c) 2007 University of British Columbia
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
package gemma.gsec.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.hibernate.LockOptions;
import org.hibernate.Session;
import org.hibernate.proxy.HibernateProxy;

/**
 * @author paul
 * @version $Id: EntityUtils.java,v 1.14 2014/03/23 17:49:20 paul Exp $
 */
public class EntityUtils {

    /**
     * Put the given entity into the Session, with LockMode.NONE
     * <p>
     * Based on idea from {@link https://forum.hibernate.org/viewtopic.php?p=2284826#p2284826}
     * 
     * @param session Hibernate Session (use factory.getCurrentSession())
     * @param obj the entity
     * @param clazz the class type of the persisted entity. Don't use obj.getClass() as this might return a proxy type.
     * @param id identifier of the obj
     */
    public static void attach( Session session, Object obj, Class<?> clazz, Long id ) {
        if ( obj == null || id == null ) return;
        if ( !session.isOpen() ) throw new IllegalArgumentException( "Illegal attempt to use a closed session" );
        if ( !session.contains( obj ) ) {

            Object oldObj = session.get( clazz, id );

            if ( oldObj != null ) {
                session.evict( oldObj );
            }
        }
        session.buildLockRequest( LockOptions.NONE ).lock( obj );
    }

    public static Long getId( Object entity ) {
        return getId( entity, "getId" );
    }

    /**
     * @param entity
     * @return
     */
    public static Long getId( Object entity, String methodName ) {
        try {
            Method m = entity.getClass().getMethod( methodName, new Class[] {} );
            return ( Long ) m.invoke( entity, new Object[] {} );
        } catch ( SecurityException e ) {
            throw new RuntimeException( e );
        } catch ( NoSuchMethodException e ) {
            throw new RuntimeException( e );
        } catch ( IllegalArgumentException e ) {
            throw new RuntimeException( e );
        } catch ( IllegalAccessException e ) {
            throw new RuntimeException( e );
        } catch ( InvocationTargetException e ) {
            throw new RuntimeException( e );
        }
    }

    /**
     * Given a set of entities, create a map of their ids to the entities.
     * 
     * @param entities where id is called "id"
     * @return
     */
    public static <T> Map<Long, T> getIdMap( Collection<? extends T> entities ) {
        Map<Long, T> result = new HashMap<Long, T>();

        for ( T object : entities ) {
            result.put( getId( object, "getId" ), object );
        }

        return result;

    }

    /**
     * @param list
     * @param fieldName e.g. "id"
     * @return
     */
    public static <T> Map<Long, T> getIdMap( Collection<? extends T> entities, String fieldName ) {
        Map<Long, T> result = new HashMap<Long, T>();

        for ( T object : entities ) {
            result.put( getId( object, fieldName ), object );
        }

        return result;
    }

    /**
     * @param entities
     * @return either a list (if entities was a list) or collection of ids.
     */
    public static Collection<Long> getIds( Collection<? extends Object> entities ) {

        Collection<Long> r;

        if ( List.class.isAssignableFrom( entities.getClass() ) ) {
            r = new ArrayList<Long>();
        } else {
            r = new HashSet<Long>();
        }

        for ( Object object : entities ) {
            r.add( getId( object ) );
        }
        return r;
    }

    /**
     * Convenience method for pushing an ID into a collection (encapsulates a common idiom)
     * 
     * @param gene
     * @return a collection with one item in it.
     */
    public static Collection<Long> getIds( Object entity ) {
        Collection<Long> r;
        r = new HashSet<Long>();
        r.add( getId( entity ) );
        return r;
    }

    public static Class<?> getImplClass( Class<?> type ) {
        String canonicalName = type.getName();
        try {
            return Class.forName( canonicalName.endsWith( "Impl" ) ? type.getName() : type.getName() + "Impl" );
        } catch ( ClassNotFoundException e ) {
            // OLDCODE throw new RuntimeException( "No 'impl' class for " + type.getCanonicalName() + " found" );
            // not all our mapped classes end with Impl any more.
            return type;
        }
    }

    /**
     * Obtain the implementation for a proxy. If target is not an instanceof HibernateProxy, target is returned.
     * 
     * @param target The object to be unproxied.
     * @return the underlying implementation.
     */
    public static Object getImplementationForProxy( Object target ) {
        if ( isProxy( target ) ) {
            HibernateProxy proxy = ( HibernateProxy ) target;
            return proxy.getHibernateLazyInitializer().getImplementation();
        }
        return target;
    }

    /**
     * @param target
     * @return true if the target is a hibernate proxy.
     */
    public static boolean isProxy( Object target ) {
        return target instanceof HibernateProxy;
    }

}
