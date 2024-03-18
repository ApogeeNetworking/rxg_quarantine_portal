import React, { useState } from "react"
import { portalApiCall } from "shared/api"

import DeleteIcon from "@mui/icons-material/Delete";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";

import { GridActionsCellItem } from "@mui/x-data-grid";

const deletePortForward = async ({
  id, deviceId, setWorking, setState, fetchAll
}) => {
  setWorking(true)

  await portalApiCall({
    collection: `devices/${deviceId}/port_forwards`,
    record_id: id,
    method: "DELETE",
    success: () => { fetchAll({ deviceId, setState }) },
    error: () => { setWorking(false) },
  })
}

const DeletePortForwardButton = ({ id, deviceId, setState, fetchAll }) => {
  const [working, setWorking] = useState(false)
  const handleClick = () => deletePortForward({
    id, deviceId, setWorking, setState, fetchAll
  })

  if (working) {
    return <GridActionsCellItem
      label="Working..." icon={<CircularProgress color="error" size="1.5em" />}
    />
  } else {
    return <GridActionsCellItem
      icon={(
        <Tooltip title={__("Delete")} placement="top" arrow><DeleteIcon /></Tooltip>
      )}
      label="Delete"
      onClick={handleClick}
      color="error"
    />
  }
}

export default DeletePortForwardButton
