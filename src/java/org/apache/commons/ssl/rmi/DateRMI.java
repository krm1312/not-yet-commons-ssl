/*
 * $HeadURL$
 * $Revision$
 * $Date$
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl.rmi;

import java.io.Serializable;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Date;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Feb-2007
 */
public class DateRMI extends UnicastRemoteObject
    implements Remote, Serializable, RemoteDate {
    private Date d;

    public DateRMI() throws RemoteException {
        super();
        this.d = new Date();
    }

    public Date getDate() throws RemoteException {
        return d;
    }

    public boolean equals(Object o) {
        RemoteDate rd = (RemoteDate) o;
        try {
            return d.equals(rd.getDate());
        }
        catch (RemoteException re) {
            return false;
        }
    }

}
