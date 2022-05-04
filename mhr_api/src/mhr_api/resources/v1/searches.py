# Copyright © 2019 Province of British Columbia
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""API endpoints for executing PPR searches."""
# pylint: disable=too-many-return-statements
from http import HTTPStatus

from flask import Blueprint
from flask import current_app, g, jsonify, request
from flask_cors import cross_origin
from registry_schemas import utils as schema_utils

from mhr_api.exceptions import BusinessException, DatabaseException
from mhr_api.models import SearchRequest, SearchResult
from mhr_api.resources import utils as resource_utils
from mhr_api.services.authz import authorized
from mhr_api.utils.auth import jwt


bp = Blueprint('SEARCHES1', __name__, url_prefix='/api/v1/searches')  # pylint: disable=invalid-name

VAL_ERROR = 'Search request data validation errors.'  # Validation error prefix
SAVE_ERROR_MESSAGE = 'Account {0} search db save failed: {1}'


@bp.route('', methods=['POST', 'OPTIONS'])
@cross_origin(origin='*')
@jwt.requires_auth
def post_searches():
    """Execute a new search request using criteria in the request body."""
    try:
        # Quick check: must be staff or provide an account ID.
        account_id = resource_utils.get_account_id(request)
        if not account_id:
            return resource_utils.account_required_response()

        # Verify request JWT and account ID
        if not authorized(account_id, jwt):
            return resource_utils.unauthorized_error_response(account_id)

        request_json = request.get_json(silent=True)
        # Validate request against the schema.
        valid_format, errors = schema_utils.validate(request_json, 'searchQuery', 'mhr')
        if not valid_format:
            return resource_utils.validation_error_response(errors, VAL_ERROR)
        # Perform any extra data validation such as start and end dates here
        SearchRequest.validate_query(request_json)
        query: SearchRequest = SearchRequest.create_from_json(request_json, account_id,
                                                              g.jwt_oidc_token_info.get('username', None))
        # Execute the search query: treat no results as a success.
        query.search()

        # Now save the initial detail results in the search_result table with no
        # search selection criteria (the absence indicates an incomplete search).
        search_result = SearchResult.create_from_search_query(query)
        search_result.save()
        return jsonify(query.json), HTTPStatus.CREATED

    except DatabaseException as db_exception:
        return resource_utils.db_exception_response(db_exception, account_id, 'POST search')
    except BusinessException as exception:
        return resource_utils.business_exception_response(exception)
    except Exception as default_exception:   # noqa: B902; return nicer default error
        return resource_utils.default_exception_response(default_exception)


@bp.route('/<string:search_id>', methods=['PUT', 'OPTIONS'])
@cross_origin(origin='*')
@jwt.requires_auth
def put_searches(search_id: str):
    """Execute a search selection update request replacing the current value with the request body contents."""
    try:
        if search_id is None:
            return resource_utils.path_param_error_response('search ID')

        # Quick check: must be staff or provide an account ID.
        account_id = resource_utils.get_account_id(request)
        if account_id is None:
            return resource_utils.account_required_response()

        # Verify request JWT and account ID
        if not authorized(account_id, jwt):
            return resource_utils.unauthorized_error_response(account_id)

        request_json = request.get_json(silent=True)
        # Validate schema.
        valid_format, errors = schema_utils.validate(request_json, 'searchSummary', 'mhr')
        if not valid_format:
            return resource_utils.validation_error_response(errors, VAL_ERROR)

        current_app.logger.info(f'put_searches update selection search ID={search_id}.')
        search_request = SearchRequest.find_by_id(search_id)
        if not search_request:
            return resource_utils.not_found_error_response('searchId', search_id)

        # Save the updated search selection.
        search_request.update_search_selection(request_json)
        return jsonify(search_request.updated_selection), HTTPStatus.ACCEPTED

    except DatabaseException as db_exception:
        return resource_utils.db_exception_response(db_exception, account_id, 'PUT search selection update')
    except BusinessException as exception:
        return resource_utils.business_exception_response(exception)
    except Exception as default_exception:   # noqa: B902; return nicer default error
        return resource_utils.default_exception_response(default_exception)