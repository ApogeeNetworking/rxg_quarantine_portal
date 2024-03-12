import React, { useState } from "react"
import { portalApiCall } from "shared/api"

import Delete from "@mui/icons-material/Delete";
import Tooltip from "@mui/material/Tooltip";
import CircularProgress from "@mui/material/CircularProgress";
import { GridActionsCellItem } from "@mui/x-data-grid";

const deleteDevice = async ({ id, setWorking, setState, fetchAll }) => {
  setWorking(true)

  await portalApiCall({
    collection: "devices",
    record_id: id,
    method: "DELETE",
    success: () => { fetchAll({ setState }) },
    error: () => { setWorking(false) },
  })
}

const DeleteDeviceButton = ({ id, setState, fetchAll }) => {
  const [working, setWorking] = useState(false)
  const handleClick = () => deleteDevice({ id, setWorking, setState, fetchAll })

  if (working) {
    return <GridActionsCellItem
      label="Working..." icon={<CircularProgress color="error" size="1.5em" />}
    />
  } else {
    return <GridActionsCellItem
      icon={(
        <Tooltip title={__("Delete")} placement="top" arrow><Delete /></Tooltip>
      )}
      label="Delete"
      onClick={handleClick}
      color="error"
    />
  }
}

export default DeleteDeviceButton
