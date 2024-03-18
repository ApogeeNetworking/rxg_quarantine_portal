import React from "react"
import AddIcon from '@mui/icons-material/Add'
import EditIcon from '@mui/icons-material/Edit'
import Button from "@mui/material/Button"


const DhcpFixedHostButton = ({ params, setDhcpFixedHostModalState }) => {
  const activateDhcpFixedHostModal = () => {
    setDhcpFixedHostModalState({
      dhcpFixedHostModalDeviceId: params.row.id,
      dhcpFixedHostModalDeviceIp: params.row.ip,
      dhcpFixedHostModalFixedHostIp: params.row.dhcp_fixed_host ? params.row.dhcp_fixed_host.ip : null,
      dhcpFixedHostModalFixedHostId: params.row.dhcp_fixed_host ? params.row.dhcp_fixed_host.id : null,
      targetIp: params.row.dhcp_fixed_host ? params.row.dhcp_fixed_host.ip : params.row.ip,
      showDhcpFixedHostModal: true
    })
  }
  return (
    <Button
      color="primary"
      startIcon={params.row.dhcp_fixed_host ? <EditIcon /> : <AddIcon />}
      onClick={activateDhcpFixedHostModal}
    >
      {params.row.dhcp_fixed_host ? __("Edit") : __("Add")}
    </Button>
  )
}

export default DhcpFixedHostButton
