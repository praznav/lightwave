/*
 * Copyright (c) 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.vmware.identity.interop.registry;

import com.vmware.identity.interop.NativeCallException;

public class RegistryNoSuchKeyOrValueException extends NativeCallException
{
	public static final int ERROR_CODE = 40700;
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 5743918586789822732L;

	public RegistryNoSuchKeyOrValueException()
	{
		super(ERROR_CODE);
	}
}
