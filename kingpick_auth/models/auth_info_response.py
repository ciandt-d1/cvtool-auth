# coding: utf-8

from __future__ import absolute_import
from .base_model_ import Model
from datetime import date, datetime
from typing import List, Dict
from ..util import deserialize_model


class AuthInfoResponse(Model):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self, id=None, email=None):
        """
        AuthInfoResponse - a model defined in Swagger

        :param id: The id of this AuthInfoResponse.
        :type id: str
        :param email: The email of this AuthInfoResponse.
        :type email: str
        """
        self.swagger_types = {
            'id': str,
            'email': str
        }

        self.attribute_map = {
            'id': 'id',
            'email': 'email'
        }

        self._id = id
        self._email = email

    @classmethod
    def from_dict(cls, dikt):
        """
        Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The AuthInfoResponse of this AuthInfoResponse.
        :rtype: AuthInfoResponse
        """
        return deserialize_model(dikt, cls)

    @property
    def id(self):
        """
        Gets the id of this AuthInfoResponse.

        :return: The id of this AuthInfoResponse.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this AuthInfoResponse.

        :param id: The id of this AuthInfoResponse.
        :type id: str
        """

        self._id = id

    @property
    def email(self):
        """
        Gets the email of this AuthInfoResponse.

        :return: The email of this AuthInfoResponse.
        :rtype: str
        """
        return self._email

    @email.setter
    def email(self, email):
        """
        Sets the email of this AuthInfoResponse.

        :param email: The email of this AuthInfoResponse.
        :type email: str
        """

        self._email = email

