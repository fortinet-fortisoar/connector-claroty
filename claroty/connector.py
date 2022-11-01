""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, check_health

logger = get_logger('claroty')


class Claroty(Connector):

    def execute(self, config, operation, params, **kwargs):
        try:
            action = operations.get(operation)
            result = action(config, params)
            return result
        except Exception as e:
            error_message = "{0}".format(str(e))
            raise ConnectorError(error_message)

    def check_health(self, config):
        try:
            res = check_health(config)
            return res
        except Exception as e:
            raise ConnectorError(str(e))
