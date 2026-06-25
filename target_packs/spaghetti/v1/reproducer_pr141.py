from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    target = Path(args.target).resolve()
    sys.path.insert(0, str(target / "src"))
    models = importlib.import_module("inca_sorter.models")
    sorting = importlib.import_module("inca_sorter.sorting")
    row_cls = models.InCARow

    def row(
        site_code: str,
        site_type: str,
        route_path: str,
        pos: int,
        row_index: int,
        site_side: str | None = None,
        ne_info: str | None = None,
        cabling_location: str = "",
        cabling_points: str = "",
    ):
        return row_cls(
            site_code,
            site_type,
            ne_info,
            cabling_location,
            cabling_points,
            "",
            None,
            route_path,
            pos,
            None,
            None,
            None,
            None,
            None,
            row_index=row_index,
            site_side=site_side,
            service_id="ICB-822677",
        )

    rows = [
        row("SEA", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 107, ne_info="sea-sea-s1 DCS-7280SR3-48Y -(..:Tx)", cabling_location="NE-location: (planned device, not yet installed)", cabling_points="0/1/49"),
        row("SEA", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 132, ne_info="sea-sea-s1 DCS-7280SR3-48Y -(..:Rx)", cabling_location="NE-location: (planned device, not yet installed)", cabling_points="0/1/49"),
        row("SEA", "XS", "SEA-SEA U 1 OL60", 1, 7, "A", "", "[13TH FL.-13050-BMMR]01/02/P2/.", "47 Cable.47"),
        row("SEA", "XS", "SEA-SEA U 1 OL60", 2, 2, "A", "", "[13TH FL.-13050-BMMR]01/02/P2/.", "48 Cable.48"),
        row("SEA", "U", "SEA-SEA U 1 OL60", 1, 5, "B", "", "[19TH FL.-STE 1901]09/04/1009/246", "47 Cable.47"),
        row("SEA", "U", "SEA-SEA U 1 OL60", 2, 23, "B", "", "[19TH FL.-STE 1901]09/04/1009/246", "48 Cable.48"),
        row("SEA", "U", "SEA U 1-SEA/2 OL04", 109, 80, "A", "", "[19TH FL.-STE 1901]12/04/07/08/.", "109 Cable.109"),
        row("SEA", "U", "SEA U 1-SEA/2 OL04", 110, 76, "A", "", "[19TH FL.-STE 1901]12/04/07/08/.", "110 Cable.110"),
        row("SEA/2", "XS", "SEA U 1-SEA/2 OL04", 109, 24, "B", "", "[6TH FL.-650.CAGE-C]3/04/PNL 4/.", "109 Cable.109"),
        row("SEA/2", "XS", "SEA U 1-SEA/2 OL04", 110, 50, "B", "", "[6TH FL.-650.CAGE-C]3/04/PNL 4/.", "110 Cable.110"),
        row("SEA/2", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 145, ne_info="SEA/2 XS DTN 01 XT-05 -(A2-3.01:Tx)", cabling_location="[6TH FL.-650.CAGE-C]2/03/RU41/.", cabling_points="05 Cable.05"),
        row("SEA/2", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 128, ne_info="SEA/2 XS DTN 01 XT-05 -(A2-3.01:Rx)", cabling_location="[6TH FL.-650.CAGE-C]2/03/RU41/.", cabling_points="06 Cable.06"),
        row("TKW", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 163, ne_info="TKW XS DTN 01 XT-05 -(A2-3.01:Tx)", cabling_location="[2ND FL.-5208B]D/4/RU38/.", cabling_points="05 Cable.05"),
        row("TKW", "XS", "SEA BR 5-TKW BR 4 100G01", 1, 148, ne_info="TKW XS DTN 01 XT-05 -(A2-3.01:Rx)", cabling_location="[2ND FL.-5208B]D/4/RU38/.", cabling_points="06 Cable.06"),
    ]
    with contextlib.redirect_stderr(io.StringIO()):
        result = sorting.sort_inca_route_path(
            rows,
            service_id="ICB-822677",
            trunk_metadata_records=[
                {"BPK_PCG": "SEA-SEA U 1 OL60", "A_SITE_CODE": "SEA", "B_SITE_CODE": "SEA", "MEDIA": "OL"},
                {"BPK_PCG": "SEA U 1-SEA/2 OL04", "A_SITE_CODE": "SEA", "B_SITE_CODE": "SEA/2", "MEDIA": "OL"},
            ],
            hub_records=[
                {"SITE_CODE": "SEA", "SITE_LOCATION_ID": "SEA00001"},
                {"SITE_CODE": "SEA/2", "SITE_LOCATION_ID": "SEA00001"},
                {"SITE_CODE": "TKW", "SITE_LOCATION_ID": "SEA00018"},
            ],
        )
    print(json.dumps({"row_indexes": [row.row_index for row in result.rows]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
