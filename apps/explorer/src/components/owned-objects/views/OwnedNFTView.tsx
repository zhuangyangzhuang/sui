// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { type DataType, type Data } from '../OwnedObjectConstants';

import { ObjectDetails } from '~/ui/ObjectDetails';

function OwnedNFT(entryObj: Data) {
    return (
        <ObjectDetails
            id={entryObj.id}
            name={entryObj.name}
            type={entryObj.name ?? entryObj.Type}
            image={entryObj.display}
            variant="small"
        />
    );
}

export default function OwnedNFTView({ results }: { results: DataType }) {
    return (
        <div className="grid grid-cols-2 gap-4">
            {results.map((entryObj) => (
                <OwnedNFT key={entryObj.id} {...entryObj} />
            ))}
        </div>
    );
}
