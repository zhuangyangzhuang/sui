// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    type SuiObjectResponse,
    getObjectId,
    getObjectDisplay,
} from '@mysten/sui.js';

import { ObjectDetails } from '~/ui/ObjectDetails';
import { extractName, parseObjectType } from '~/utils/objectUtils';
import { trimStdLibPrefix } from '~/utils/stringUtils';

type OwnedObjectTypes = {
    obj: SuiObjectResponse;
};

function OwnedObject({ obj }: OwnedObjectTypes): JSX.Element {
    const displayMeta = getObjectDisplay(obj).data;

    return (
        <ObjectDetails
            id={getObjectId(obj)}
            name={extractName(displayMeta) ?? ''}
            variant="small"
            type={trimStdLibPrefix(parseObjectType(obj))}
            image={displayMeta?.image_url}
        />
    );
}

export default OwnedObject;
